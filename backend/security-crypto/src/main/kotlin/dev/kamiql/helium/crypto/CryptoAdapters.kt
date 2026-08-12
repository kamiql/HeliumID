package dev.kamiql.helium.crypto

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.crypto.EncryptedSecret
import dev.kamiql.helium.domain.crypto.KeyProvider
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.SecretCipher
import dev.kamiql.helium.domain.crypto.TokenHasher
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The single entropy source for the whole system.
 *
 * `SecureRandom()` rather than `getInstanceStrong()`: on Linux the latter reads
 * `/dev/random` through the `NativePRNGBlocking` provider and can block for minutes in a fresh
 * container. The default is seeded from the OS CSPRNG and is the right choice for token
 * generation.
 */
class SecureRandomSource : RandomSource {

    private val random = SecureRandom()
    private val urlEncoder = Base64.getUrlEncoder().withoutPadding()

    override fun bytes(length: Int): ByteArray = ByteArray(length).also(random::nextBytes)

    override fun token(byteLength: Int): String = urlEncoder.encodeToString(bytes(byteLength))

    /**
     * A code a human can read off a printout and type back.
     *
     * The alphabet omits `0/O`, `1/I/L` and `U` (which is easily read as `V` in some fonts).
     * 32 symbols is 5 bits each, so the default 10 symbols carry 50 bits — ample for a
     * rate-limited, single-use recovery code.
     */
    override fun humanCode(groups: Int, groupLength: Int): String =
        (0 until groups).joinToString("-") {
            (0 until groupLength)
                .map { CODE_ALPHABET[random.nextInt(CODE_ALPHABET.length)] }
                .joinToString("")
        }

    private companion object {
        const val CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
    }
}

/**
 * HMAC-SHA-256 token hashing (concept §4.3).
 *
 * Keyed, so a stolen database cannot be used to look up tokens the attacker guesses; fast,
 * because the inputs are already 256-bit random values and stretching them buys nothing.
 *
 * Rotating [KeyProvider.tokenHmacKey] invalidates every stored hash at once — every session,
 * refresh token and pending reset link. That is a valid break-glass action but never routine.
 */
class HmacTokenHasher(keyProvider: KeyProvider) : TokenHasher {

    private val key = SecretKeySpec(keyProvider.tokenHmacKey(), ALGORITHM)
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    override fun hash(token: String): String {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(key)
        return encoder.encodeToString(mac.doFinal(token.toByteArray(Charsets.UTF_8)))
    }

    override fun matches(token: String, hash: String): Boolean =
        MessageDigest.isEqual(
            hash(token).toByteArray(Charsets.UTF_8),
            hash.toByteArray(Charsets.UTF_8),
        )

    private companion object {
        const val ALGORITHM = "HmacSHA256"
    }
}

/**
 * AES-256-GCM for secrets the server must recover: TOTP shared secrets and signing keys.
 *
 * GCM is authenticated, so tampering with stored ciphertext fails loudly rather than yielding
 * a wrong-but-plausible plaintext. The 96-bit nonce is random per encryption — with a fresh
 * nonce every time and a key rotated long before 2^32 operations, reuse is not a practical
 * concern; a counter would be, since this runs on many instances at once.
 */
class AesGcmSecretCipher(
    private val keyProvider: KeyProvider,
    private val random: RandomSource,
) : SecretCipher {

    override val currentKeyVersion: Int get() = keyProvider.currentDataKeyVersion

    override fun encrypt(plaintext: ByteArray): EncryptedSecret {
        val version = keyProvider.currentDataKeyVersion
        val nonce = random.bytes(NONCE_BYTES)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(keyProvider.dataEncryptionKey(version), "AES"),
            GCMParameterSpec(TAG_BITS, nonce),
        )
        // The key version is authenticated, so ciphertext cannot be replayed under another key.
        cipher.updateAAD(version.toString().toByteArray(Charsets.UTF_8))
        return EncryptedSecret(cipher.doFinal(plaintext), nonce, version)
    }

    /** @throws IllegalStateException on an unknown key version or a failed authentication tag. */
    override fun decrypt(secret: EncryptedSecret): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(keyProvider.dataEncryptionKey(secret.keyVersion), "AES"),
            GCMParameterSpec(TAG_BITS, secret.nonce),
        )
        cipher.updateAAD(secret.keyVersion.toString().toByteArray(Charsets.UTF_8))
        return try {
            cipher.doFinal(secret.ciphertext)
        } catch (error: javax.crypto.AEADBadTagException) {
            // Fail closed (§7.6): wrong key or tampered data, never a partial result.
            throw IllegalStateException("failed to authenticate encrypted secret", error)
        }
    }
}

/**
 * Key material from configuration.
 *
 * This is the local implementation of the [KeyProvider] port. It is a legitimate choice for
 * development and for deployments whose secret manager already injects environment variables
 * (Vault Agent, Kubernetes secrets from an external store). A KMS/HSM implementation replaces
 * it without any caller changing — the interface is deliberately narrow for exactly that.
 *
 * @param dataKeys version to raw 32-byte key. Old versions must be kept so previously
 *        encrypted values remain readable (concept §7.2).
 * @param peppers version to pepper. Empty disables peppering.
 */
class LocalKeyProvider(
    private val dataKeys: Map<Int, ByteArray>,
    override val currentDataKeyVersion: Int,
    private val tokenHmacKey: ByteArray,
    private val peppers: Map<Int, Secret> = emptyMap(),
    override val currentPepperVersion: Int = 0,
) : KeyProvider {

    init {
        require(dataKeys.containsKey(currentDataKeyVersion)) {
            "current data key version $currentDataKeyVersion is not configured"
        }
        dataKeys.forEach { (version, key) ->
            require(key.size == 32) { "data key v$version must be 32 bytes, was ${key.size}" }
        }
        require(tokenHmacKey.size >= 32) { "token HMAC key must be at least 32 bytes" }
    }

    override fun dataEncryptionKey(version: Int): ByteArray =
        dataKeys[version] ?: error("data key version $version is not configured")

    override fun tokenHmacKey(): ByteArray = tokenHmacKey.copyOf()

    override fun passwordPepper(version: Int): Secret? = peppers[version]

    companion object {
        /**
         * Builds a provider from base64 configuration values.
         *
         * @param dataKeysBase64 `version:base64` entries, e.g. `1:AAA…,2:BBB…`.
         * @throws IllegalArgumentException on malformed input — a misconfigured key must stop
         *         the process at boot, not surface later as an undecryptable TOTP secret.
         */
        fun fromBase64(
            dataKeysBase64: String,
            currentVersion: Int,
            tokenHmacKeyBase64: String,
            pepperBase64: String? = null,
            pepperVersion: Int = 0,
        ): LocalKeyProvider {
            val decoder = Base64.getDecoder()
            val keys = dataKeysBase64.split(',')
                .filter { it.isNotBlank() }
                .associate { entry ->
                    val (version, value) = entry.split(':', limit = 2)
                    version.trim().toInt() to decoder.decode(value.trim())
                }
            require(keys.isNotEmpty()) { "at least one data encryption key must be configured" }

            val peppers = pepperBase64
                ?.takeIf { it.isNotBlank() }
                ?.let { mapOf(pepperVersion to Secret.ofBytes(decoder.decode(it))) }
                .orEmpty()

            return LocalKeyProvider(
                dataKeys = keys,
                currentDataKeyVersion = currentVersion,
                tokenHmacKey = decoder.decode(tokenHmacKeyBase64),
                peppers = peppers,
                currentPepperVersion = if (peppers.isEmpty()) 0 else pepperVersion,
            )
        }
    }
}

private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val NONCE_BYTES = 12
private const val TAG_BITS = 128
