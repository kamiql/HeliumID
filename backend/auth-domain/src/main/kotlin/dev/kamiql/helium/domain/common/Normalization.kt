package dev.kamiql.helium.domain.common

import java.text.Normalizer
import java.util.Locale

/**
 * The single normalization policy for the whole system.
 *
 * Concept §3.3: "Define the normalization policy centrally; do not let individual routes
 * normalize differently." Every uniqueness check, lookup and rate-limit key derives from the
 * `normalized` form; the `display` form is what the user typed and is only ever shown back.
 */
object Normalization {

    /** Unicode NFKC + Unicode-aware lowercasing, using [Locale.ROOT] to avoid the Turkish-I trap. */
    fun fold(raw: String): String =
        Normalizer.normalize(raw.trim(), Normalizer.Form.NFKC).lowercase(Locale.ROOT)
}

/**
 * A username as typed plus its normalized lookup key.
 *
 * Construct through [Username.parse] so the policy is applied exactly once.
 */
class Username private constructor(
    val display: String,
    val normalized: String,
) {
    override fun equals(other: Any?): Boolean = other is Username && other.normalized == normalized

    override fun hashCode(): Int = normalized.hashCode()

    override fun toString(): String = display

    companion object {
        const val MIN_LENGTH: Int = 3
        const val MAX_LENGTH: Int = 32

        /** Letters, digits, dot, dash and underscore. Deliberately narrow to keep lookalikes out. */
        private val ALLOWED = Regex("^[a-z0-9._-]+$")

        /**
         * Returns the parsed username, or `null` when it violates policy.
         *
         * Callers translate `null` into
         * [dev.kamiql.helium.domain.error.AuthError.ValidationFailed]; the domain never throws
         * for user input.
         */
        fun parse(raw: String): Username? {
            val normalized = Normalization.fold(raw)
            if (normalized.length < MIN_LENGTH || normalized.length > MAX_LENGTH) return null
            if (!ALLOWED.matches(normalized)) return null
            // A username that could be mistaken for an email invites confusion at login.
            if (normalized.contains('@')) return null
            return Username(raw.trim(), normalized)
        }

        /** Rehydrates a value already persisted in normalized form. */
        fun restore(display: String, normalized: String): Username = Username(display, normalized)
    }
}

/**
 * An email address as typed plus its normalized lookup key.
 *
 * Normalization is case folding only. Provider-specific tricks (stripping dots, cutting at
 * `+`) are deliberately **not** applied: they would let one mailbox claim many accounts, or
 * worse, let two different mailboxes collide onto one row.
 */
class EmailAddress private constructor(
    val display: String,
    val normalized: String,
) {
    val domain: String get() = normalized.substringAfterLast('@')

    override fun equals(other: Any?): Boolean = other is EmailAddress && other.normalized == normalized

    override fun hashCode(): Int = normalized.hashCode()

    override fun toString(): String = display

    companion object {
        const val MAX_LENGTH: Int = 320

        /**
         * Intentionally permissive. Full RFC 5322 validation is a known source of false
         * rejections; deliverability is proven by the verification mail, not by a regex.
         */
        private val SHAPE = Regex("^[^@\\s]+@[^@\\s.]+(\\.[^@\\s.]+)+$")

        fun parse(raw: String): EmailAddress? {
            val trimmed = raw.trim()
            if (trimmed.length > MAX_LENGTH) return null
            val normalized = Normalization.fold(trimmed)
            if (!SHAPE.matches(normalized)) return null
            return EmailAddress(trimmed, normalized)
        }

        fun restore(display: String, normalized: String): EmailAddress = EmailAddress(display, normalized)
    }
}
