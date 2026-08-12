package dev.kamiql.helium.oauth

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.token.CodeChallengeMethod
import java.security.MessageDigest
import java.util.Base64

/**
 * PKCE (RFC 7636), S256 only.
 *
 * `plain` is not implemented and must not be: it offers no protection against an attacker who
 * can observe the authorization request, which is the entire threat PKCE addresses. CLAUDE.md
 * and concept §5.1 both mandate S256.
 */
object Pkce {

    /** RFC 7636 §4.1: 43–128 characters from the unreserved set. */
    private val VERIFIER_SHAPE = Regex("^[A-Za-z0-9\\-._~]{43,128}$")

    /**
     * Validates a challenge as supplied in the authorization request.
     *
     * @return the parsed method, or `null` if the challenge is missing, malformed, or uses an
     *         unsupported transform. A missing challenge is a rejection, not a downgrade to
     *         `plain`.
     */
    fun validateChallenge(challenge: String?, method: String?): CodeChallengeMethod? {
        if (challenge.isNullOrBlank()) return null
        // An S256 challenge is a base64url SHA-256 digest: 43 characters, unpadded.
        if (challenge.length !in 43..128) return null
        if (!challenge.all { it.isLetterOrDigit() || it in "-._~" }) return null
        return CodeChallengeMethod.parse(method)
    }

    /**
     * Checks a verifier against the stored challenge.
     *
     * The comparison is constant time — a timing side channel here would let an attacker
     * recover the challenge one character at a time.
     */
    fun verify(verifier: Secret, storedChallenge: String, method: CodeChallengeMethod): Boolean {
        val raw = verifier.reveal()
        if (!VERIFIER_SHAPE.matches(raw)) return false

        val computed = when (method) {
            CodeChallengeMethod.S256 -> challengeFor(raw)
        }
        return MessageDigest.isEqual(
            computed.toByteArray(Charsets.US_ASCII),
            storedChallenge.toByteArray(Charsets.US_ASCII),
        )
    }

    /** `BASE64URL(SHA256(ASCII(verifier)))`, unpadded. Exposed for tests and the SDK. */
    fun challengeFor(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
