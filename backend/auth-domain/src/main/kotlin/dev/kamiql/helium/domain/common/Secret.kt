package dev.kamiql.helium.domain.common

import java.security.MessageDigest
import java.util.Arrays

/**
 * A value that must never reach a log, a stack trace, an exception message or a serialized
 * payload.
 *
 * [toString] is deliberately lossy, [equals] is constant time and the raw characters are only
 * reachable through [use] / [reveal], which are easy to grep for during review.
 *
 * Concept §8.2: "`Secret` should prevent accidental logging."
 */
class Secret private constructor(private val bytes: ByteArray) {

    /** Length in UTF-8 bytes. Safe to log — it carries no content. */
    val byteLength: Int get() = bytes.size

    /** Runs [block] with the plaintext. Do not let the value escape the lambda. */
    fun <T> use(block: (CharArray) -> T): T {
        val chars = String(bytes, Charsets.UTF_8).toCharArray()
        return try {
            block(chars)
        } finally {
            // Zero the working copy so a retained reference is not a retained password.
            Arrays.fill(chars, '\u0000')
        }
    }

    /**
     * Returns the plaintext. Only call this at the boundary of an audited cryptographic
     * primitive (password hashing, HMAC, cipher input).
     */
    fun reveal(): String = String(bytes, Charsets.UTF_8)

    /** Raw UTF-8 bytes for cryptographic primitives that take a byte array. */
    fun revealBytes(): ByteArray = bytes.copyOf()

    /** Constant-time comparison; never short-circuits on the first differing byte. */
    override fun equals(other: Any?): Boolean =
        other is Secret && MessageDigest.isEqual(bytes, other.bytes)

    override fun hashCode(): Int = bytes.size

    override fun toString(): String = REDACTED

    companion object {
        const val REDACTED: String = "Secret(redacted)"

        fun of(value: String): Secret = Secret(value.toByteArray(Charsets.UTF_8))

        fun of(value: CharArray): Secret = Secret(String(value).toByteArray(Charsets.UTF_8))

        fun ofBytes(value: ByteArray): Secret = Secret(value.copyOf())
    }
}
