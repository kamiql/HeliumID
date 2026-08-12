package dev.kamiql.helium.crypto

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.credential.PasswordHash
import dev.kamiql.helium.domain.credential.PasswordHashParameters
import dev.kamiql.helium.domain.credential.PasswordHasher
import dev.kamiql.helium.domain.crypto.KeyProvider
import dev.kamiql.helium.domain.crypto.RandomSource
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.Executors

/**
 * Argon2id password hashing on Bouncy Castle.
 *
 * Bouncy Castle rather than a JNI binding: no native library to ship per platform, and the
 * implementation is widely reviewed. CLAUDE.md forbids implementing the KDF itself, and
 * nothing here does — this class only encodes, decodes and schedules.
 *
 * **Thread pool sizing is a security control.** A single Argon2id verification holds
 * `memoryKib` of heap for its whole duration; at the default 64 MiB, thirty concurrent
 * verifications is 1.9 GiB. Verification therefore runs on its own small, bounded pool
 * ([hashingDispatcher]) so a burst of login attempts queues instead of exhausting the heap or
 * starving the request threads (concept §4.1: "Password verification must not exhaust the
 * application thread pool").
 *
 * @param parallelismLimit concurrent hash operations. Multiply by `memoryKib` to get the
 *        worst-case heap this component can occupy, and size it against the container limit.
 */
class Argon2idPasswordHasher(
    private val parameters: PasswordHashParameters = PasswordHashParameters.DEFAULT,
    private val random: RandomSource,
    private val keyProvider: KeyProvider,
    parallelismLimit: Int = 4,
    hashingDispatcher: CoroutineDispatcher? = null,
) : PasswordHasher {

    private val dispatcher: CoroutineDispatcher = hashingDispatcher
        ?: Executors.newFixedThreadPool(parallelismLimit) { runnable ->
            Thread(runnable, "argon2-worker").apply { isDaemon = true }
        }.asCoroutineDispatcher()

    /**
     * The pepper version comes from the [KeyProvider], not from [parameters].
     *
     * Otherwise a deployment that configures a pepper but forgets to bump the version variable
     * would silently hash without it — a security control that is off while appearing to be on.
     * The version actually used is then recorded with the hash so verification can reproduce it.
     */
    private val effectiveParameters: PasswordHashParameters
        get() = parameters.copy(pepperVersion = keyProvider.currentPepperVersion)

    override suspend fun hash(password: Secret): PasswordHash = withContext(dispatcher) {
        val active = effectiveParameters
        val salt = random.bytes(active.saltLength)
        val digest = derive(password, salt, active)
        PasswordHash(
            algorithm = ALGORITHM,
            encoded = encode(salt, digest, active),
            parameters = active,
        )
    }

    /**
     * Verifies against the parameters stored **with the hash**, not the current configuration,
     * so raising the cost factor does not lock out existing users.
     */
    override suspend fun verify(password: Secret, hash: PasswordHash): Boolean = withContext(dispatcher) {
        val decoded = decode(hash.encoded) ?: return@withContext false
        val candidate = derive(password, decoded.salt, decoded.parameters)
        // Constant-time: comparing with `contentEquals` would leak the matching prefix length.
        MessageDigest.isEqual(candidate, decoded.hash)
    }

    /**
     * Burns an equivalent amount of work and always fails.
     *
     * Without this, "no such account" returns in microseconds while "wrong password" takes
     * hundreds of milliseconds, and the difference is a free user-enumeration oracle.
     */
    override suspend fun verifyDummy(password: Secret): Boolean = withContext(dispatcher) {
        derive(password, DUMMY_SALT, effectiveParameters)
        false
    }

    override fun needsRehash(hash: PasswordHash): Boolean {
        if (hash.algorithm != ALGORITHM) return true
        val stored = hash.parameters
        return stored.memoryKib < parameters.memoryKib ||
            stored.iterations < parameters.iterations ||
            stored.hashLength < parameters.hashLength ||
            stored.pepperVersion != keyProvider.currentPepperVersion
    }

    /**
     * Applies the optional server-side pepper before the KDF.
     *
     * The pepper lives in the KMS, never in the database, so a database-only leak leaves the
     * attacker unable to test candidate passwords offline (concept §4.1).
     */
    private fun derive(password: Secret, salt: ByteArray, params: PasswordHashParameters): ByteArray {
        val pepper = keyProvider.passwordPepper(params.pepperVersion)
        val input = if (pepper == null) {
            password.revealBytes()
        } else {
            password.revealBytes() + pepper.revealBytes()
        }

        val generator = Argon2BytesGenerator()
        generator.init(
            Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(params.memoryKib)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
                .withSalt(salt)
                .build(),
        )
        val output = ByteArray(params.hashLength)
        generator.generateBytes(input, output)
        java.util.Arrays.fill(input, 0)
        return output
    }

    /** PHC string format, so the stored value is self-describing and portable. */
    private fun encode(salt: ByteArray, hash: ByteArray, params: PasswordHashParameters): String {
        val encoder = Base64.getEncoder().withoutPadding()
        return "\$argon2id\$v=19\$m=${params.memoryKib},t=${params.iterations},p=${params.parallelism}" +
            "\$${encoder.encodeToString(salt)}\$${encoder.encodeToString(hash)}" +
            "\$pv=${params.pepperVersion}"
    }

    private fun decode(encoded: String): DecodedHash? {
        val parts = encoded.split('$').filter { it.isNotEmpty() }
        // argon2id | v=19 | m=..,t=..,p=.. | salt | hash | pv=..
        if (parts.size < 5 || parts[0] != "argon2id") return null
        return try {
            val costs = parts[2].split(',').associate { entry ->
                val (name, value) = entry.split('=')
                name to value.toInt()
            }
            val decoder = Base64.getDecoder()
            val salt = decoder.decode(parts[3])
            val hash = decoder.decode(parts[4])
            val pepperVersion = parts.getOrNull(5)
                ?.removePrefix("pv=")?.toIntOrNull()
                ?: 0
            DecodedHash(
                salt = salt,
                hash = hash,
                parameters = PasswordHashParameters(
                    memoryKib = costs.getValue("m"),
                    iterations = costs.getValue("t"),
                    parallelism = costs.getValue("p"),
                    saltLength = salt.size,
                    hashLength = hash.size,
                    pepperVersion = pepperVersion,
                ),
            )
        } catch (_: Exception) {
            // A malformed stored hash must fail verification, never throw into the login path.
            null
        }
    }

    private class DecodedHash(
        val salt: ByteArray,
        val hash: ByteArray,
        val parameters: PasswordHashParameters,
    )

    companion object {
        const val ALGORITHM: String = "argon2id"

        /** Fixed salt: this derivation's output is discarded, only its cost matters. */
        private val DUMMY_SALT = ByteArray(16) { it.toByte() }
    }
}
