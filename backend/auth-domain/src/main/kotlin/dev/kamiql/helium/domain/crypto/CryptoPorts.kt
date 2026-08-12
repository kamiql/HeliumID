package dev.kamiql.helium.domain.crypto

import dev.kamiql.helium.domain.common.Secret
import java.time.Clock
import java.time.Instant

/**
 * Source of "now" for the whole system.
 *
 * Everything that expires takes its time from here so that tests can advance the clock instead
 * of sleeping, and so no code path can accidentally use the machine's local zone. All values
 * are UTC (CLAUDE.md: "Use UTC timestamps").
 */
fun interface HeliumClock {
    fun now(): Instant

    companion object {
        val SYSTEM: HeliumClock = HeliumClock { Clock.systemUTC().instant() }
    }
}

/**
 * Cryptographically secure randomness.
 *
 * A port rather than a direct `SecureRandom` call so tests can pin values, and so every
 * generated secret goes through one reviewed implementation with one entropy source.
 */
interface RandomSource {

    fun bytes(length: Int): ByteArray

    /**
     * A URL-safe, unpadded base64 token.
     *
     * @param byteLength entropy in bytes before encoding; 32 (256 bits) for anything
     *        long-lived, per concept §2.6.
     */
    fun token(byteLength: Int = 32): String

    /**
     * A human-transcribable code from an unambiguous alphabet (no `0`/`O`, `1`/`I`).
     * Used for recovery codes.
     */
    fun humanCode(groups: Int = 2, groupLength: Int = 5): String
}

/**
 * Keyed one-way hashing for token lookup.
 *
 * Refresh tokens, session cookies, authorization codes, reset and verification tokens are all
 * high-entropy random values, so a fast keyed HMAC is correct here — a slow password hash
 * would add latency without adding security, and a *plain* hash would let an attacker with a
 * database dump build a rainbow table for the token space they can guess.
 *
 * Concept §4.3: `HMAC-SHA-256(server_pepper, refresh_token)`.
 */
interface TokenHasher {

    /** Deterministic, so the hash can be used as a lookup key. */
    fun hash(token: String): String

    /** Constant-time comparison of a presented token against a stored hash. */
    fun matches(token: String, hash: String): Boolean
}

/**
 * Authenticated encryption for secrets the server must later recover in plaintext — currently
 * TOTP shared secrets and signing key material.
 *
 * The key version travels with the ciphertext so keys can be rotated while old data stays
 * readable (concept §7.2).
 */
interface SecretCipher {

    fun encrypt(plaintext: ByteArray): EncryptedSecret

    /**
     * @throws IllegalStateException if [EncryptedSecret.keyVersion] is unknown, which is a
     *         configuration error and must fail closed rather than silently return garbage.
     */
    fun decrypt(secret: EncryptedSecret): ByteArray

    /** Version new ciphertext is written with. Anything older is a re-encryption candidate. */
    val currentKeyVersion: Int
}

/**
 * AES-256-GCM ciphertext with its nonce and the key version used.
 *
 * @param ciphertext includes the GCM authentication tag.
 */
class EncryptedSecret(
    val ciphertext: ByteArray,
    val nonce: ByteArray,
    val keyVersion: Int,
) {
    /** Single-column storage form: `v1.<base64 nonce>.<base64 ciphertext>`. */
    fun encode(): String {
        val encoder = java.util.Base64.getEncoder().withoutPadding()
        return "v$keyVersion.${encoder.encodeToString(nonce)}.${encoder.encodeToString(ciphertext)}"
    }

    override fun toString(): String = "EncryptedSecret(v$keyVersion, redacted)"

    companion object {
        fun decode(encoded: String): EncryptedSecret? {
            val parts = encoded.split('.')
            if (parts.size != 3 || !parts[0].startsWith("v")) return null
            val version = parts[0].drop(1).toIntOrNull() ?: return null
            return try {
                val decoder = java.util.Base64.getDecoder()
                EncryptedSecret(
                    ciphertext = decoder.decode(parts[2]),
                    nonce = decoder.decode(parts[1]),
                    keyVersion = version,
                )
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}

/**
 * Supplies raw key material.
 *
 * The local implementation reads base64 keys from configuration; a KMS/HSM implementation
 * replaces it without any caller changing. CLAUDE.md: "Encrypt TOTP secrets and other
 * recoverable secrets with KMS-managed keys."
 */
interface KeyProvider {

    /** @throws IllegalStateException when [version] is not configured. Fail closed (§7.6). */
    fun dataEncryptionKey(version: Int): ByteArray

    val currentDataKeyVersion: Int

    /** Key for [TokenHasher]. Rotating it invalidates every stored token hash at once. */
    fun tokenHmacKey(): ByteArray

    /** Optional server-side password pepper (concept §4.1). `null` disables peppering. */
    fun passwordPepper(version: Int): Secret?

    val currentPepperVersion: Int
}
