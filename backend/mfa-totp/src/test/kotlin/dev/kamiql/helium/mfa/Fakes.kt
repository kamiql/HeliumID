package dev.kamiql.helium.mfa

import dev.kamiql.helium.crypto.AesGcmSecretCipher
import dev.kamiql.helium.crypto.HmacTokenHasher
import dev.kamiql.helium.crypto.LocalKeyProvider
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.crypto.EncryptedSecret
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.SecretCipher
import dev.kamiql.helium.domain.crypto.TokenHasher
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.RecoveryCode
import dev.kamiql.helium.domain.mfa.TotpFactor
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import io.mockk.coEvery
import io.mockk.mockk
import java.time.Instant

/**
 * In-memory doubles for the two ports the TOTP and recovery-code adapters drive.
 *
 * Fakes rather than mocks because every interesting property here is a property of *state over
 * time*: a time step that was already burned, a recovery code that was already spent, a pending
 * factor that a restarted enrollment revoked. Per-call stubs would happily answer "yes" twice
 * and the replay tests — the whole point of the suite — would pass against a broken adapter.
 *
 * The two conditional updates are copied from the port contract rather than approximated:
 * [tryAdvanceTotpStep] accepts only a strictly greater step and [consumeRecoveryCode] only an
 * unused row, because both are the single SQL statement that makes concurrent replay lose.
 */
internal class InMemoryMfaRepository : MfaRepository {

    private val factors = linkedMapOf<MfaFactorId, MfaFactor>()
    private val totpRows = linkedMapOf<MfaFactorId, TotpFactor>()
    private val recoveryRows = mutableListOf<RecoveryCode>()

    /** How many times the whole recovery-code set was swapped; regeneration must replace, not append. */
    var recoveryCodeReplacements: Int = 0
        private set

    override suspend fun listFactors(userId: UserId): List<MfaFactor> =
        factors.values.filter { it.userId == userId }

    override suspend fun findFactor(id: MfaFactorId): MfaFactor? = factors[id]

    override suspend fun findActiveFactorOfType(userId: UserId, type: MfaType): MfaFactor? =
        factors.values.firstOrNull { it.userId == userId && it.type == type && it.isActive }

    override suspend fun insertFactor(factor: MfaFactor): MfaFactor {
        factors[factor.id] = factor
        return factor
    }

    override suspend fun activateFactor(id: MfaFactorId, at: Instant) {
        factors.computeIfPresent(id) { _, factor -> factor.copy(status = MfaFactorStatus.ACTIVE) }
    }

    override suspend fun relabelFactor(id: MfaFactorId, label: String) {
        factors.computeIfPresent(id) { _, factor -> factor.copy(label = label) }
    }

    override suspend fun revokeFactor(id: MfaFactorId, at: Instant) {
        factors.computeIfPresent(id) { _, factor -> factor.copy(status = MfaFactorStatus.REVOKED) }
    }

    override suspend fun touchFactor(id: MfaFactorId, at: Instant) {
        factors.computeIfPresent(id) { _, factor -> factor.copy(lastUsedAt = at) }
    }

    override suspend fun findTotp(factorId: MfaFactorId): TotpFactor? = totpRows[factorId]

    override suspend fun insertTotp(factor: TotpFactor) {
        totpRows[factor.factorId] = factor
    }

    override suspend fun tryAdvanceTotpStep(factorId: MfaFactorId, step: Long): Boolean {
        val row = totpRows[factorId] ?: return false
        val last = row.lastAcceptedStep
        if (last != null && step <= last) return false
        totpRows[factorId] = row.copy(lastAcceptedStep = step)
        return true
    }

    override suspend fun replaceRecoveryCodes(userId: UserId, codes: List<RecoveryCode>) {
        recoveryCodeReplacements++
        recoveryRows.removeAll { it.userId == userId }
        recoveryRows += codes
    }

    override suspend fun listRecoveryCodes(userId: UserId): List<RecoveryCode> =
        recoveryRows.filter { it.userId == userId }

    override suspend fun consumeRecoveryCode(userId: UserId, codeHash: String, at: Instant): Boolean {
        // Scoped to the user on purpose: a hash resolved globally would let one account's code
        // authenticate another's, which is exactly the substitution the SQL predicate prevents.
        val index = recoveryRows.indexOfFirst {
            it.userId == userId && it.codeHash == codeHash && it.usedAt == null
        }
        if (index < 0) return false
        recoveryRows[index] = recoveryRows[index].copy(usedAt = at)
        return true
    }

    override suspend fun countUnusedRecoveryCodes(userId: UserId): Int =
        recoveryRows.count { it.userId == userId && it.usedAt == null }
}

/**
 * A [RandomSource] whose secret bytes are pinned.
 *
 * The default is the 20-byte ASCII string RFC 6238 publishes its test vectors against, so an
 * enrollment driven through the real adapter produces the secret the RFC's known answers belong
 * to. That turns "our TOTP works" from a claim about our own code generator into a claim
 * checkable against the standard.
 */
internal class FixedSecretRandomSource(
    private val secret: ByteArray = RFC_6238_SHA1_SECRET,
) : RandomSource {

    private var codes = 0

    override fun bytes(length: Int): ByteArray = secret.copyOf(length)

    override fun token(byteLength: Int): String = error("the TOTP adapter does not issue tokens")

    /** Two groups of five, dash separated — the shape [RecoveryCodeMfaMethod] normalizes away. */
    override fun humanCode(groups: Int, groupLength: Int): String {
        codes++
        return (0 until groups).joinToString("-") { group ->
            ('A' + ((codes + group) % 20)).toString().repeat(groupLength)
        }
    }

    companion object {
        /** `12345678901234567890`, the seed in RFC 6238 Appendix B. */
        val RFC_6238_SHA1_SECRET: ByteArray = "12345678901234567890".toByteArray(Charsets.US_ASCII)

        /** Base32 of the above, which is what the adapter stores and shows the user. */
        const val RFC_6238_SHA1_SECRET_BASE32: String = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    }
}

/**
 * Wraps the real AES-GCM cipher and counts calls.
 *
 * Counting is what makes the cheap-rejection tests meaningful: "a six-letter word is refused" is
 * uninteresting, but "a six-letter word is refused *without decrypting the secret*" is the
 * property that keeps a malformed-input flood from turning into a KMS bill.
 */
internal class CountingSecretCipher(private val delegate: SecretCipher) : SecretCipher {

    var decryptions: Int = 0
        private set

    override fun encrypt(plaintext: ByteArray): EncryptedSecret = delegate.encrypt(plaintext)

    override fun decrypt(secret: EncryptedSecret): ByteArray {
        decryptions++
        return delegate.decrypt(secret)
    }

    override val currentKeyVersion: Int get() = delegate.currentKeyVersion
}

/** Real AES-256-GCM over a fixed key set, so the encrypted-at-rest path is the shipping one. */
internal fun secretCipher(vararg versions: Int): SecretCipher = AesGcmSecretCipher(
    keyProvider = keyProvider(*versions),
    random = FixedSecretRandomSource(ByteArray(32) { it.toByte() }),
)

internal fun keyProvider(vararg versions: Int): LocalKeyProvider = LocalKeyProvider(
    dataKeys = versions.associateWith { version -> ByteArray(32) { version.toByte() } },
    currentDataKeyVersion = versions.first(),
    tokenHmacKey = ByteArray(32) { 9 },
)

/** Real HMAC-SHA-256, so "the stored code is hashed" is a claim about the shipping hasher. */
internal fun tokenHasher(): TokenHasher = HmacTokenHasher(keyProvider(1))

/**
 * The account being enrolled.
 *
 * A mock is right here and nowhere else in the suite: the adapter reads one immutable row and
 * never writes, so there is no state for a fake to get wrong.
 */
internal fun userRepositoryFor(userId: UserId, email: String = "ada@example.com"): UserRepository =
    mockk<UserRepository>().also {
        coEvery { it.findById(userId) } returns User(
            id = userId,
            username = Username.restore("ada", "ada"),
            primaryEmail = EmailAddress.restore(email, email.lowercase()),
            firstName = "Ada",
            lastName = "Lovelace",
            status = UserStatus.ACTIVE,
            emailVerifiedAt = Instant.EPOCH,
            createdAt = Instant.EPOCH,
            updatedAt = Instant.EPOCH,
            version = 1L,
        )
        coEvery { it.findById(neq(userId)) } returns null
    }
