package dev.kamiql.helium.client

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * PKCE (RFC 7636), S256 only.
 *
 * Hand-rolling this is where integrations go wrong: a verifier from `Math.random()`, a
 * challenge that is base64 instead of base64url, or a fallback to `plain` when SHA-256 is
 * inconvenient. All three defeat the point. HeliumID rejects `plain` outright — it offers no
 * protection against an attacker who can observe the authorization request, which is the entire
 * threat PKCE addresses — so this helper only ever produces S256.
 *
 * Usage:
 * ```kotlin
 * // 1. Before redirecting the user agent to /oauth2/authorize:
 * val verifier = Pkce.generateVerifier()
 * val challenge = Pkce.challengeFor(verifier)
 * // Keep `verifier` server-side (or in sessionStorage for a SPA) — never in the URL.
 *
 * // 2. On the callback, exchange the code with the verifier you kept:
 * val tokens = client.exchangeAuthorizationCode(
 *     code = code, redirectUri = redirectUri, clientId = clientId, codeVerifier = verifier,
 * )
 * ```
 */
public object Pkce {

    /** RFC 7636 §4.1 permits 43–128 characters from the unreserved set. */
    private const val DEFAULT_VERIFIER_BYTES: Int = 32

    private val UNRESERVED = Regex("^[A-Za-z0-9\\-._~]{43,128}$")

    /**
     * A cryptographically random code verifier.
     *
     * 32 bytes of [SecureRandom] rendered as unpadded base64url — 43 characters, the RFC's
     * minimum length and its recommended entropy. There is no reason to want a longer one; the
     * parameter exists only so a caller with a specific policy can meet it.
     *
     * @param entropyBytes raw randomness before encoding. Must be 32–96, which maps to the
     *        43–128 character range the specification allows.
     * @throws IllegalArgumentException if [entropyBytes] is outside that range.
     */
    public fun generateVerifier(entropyBytes: Int = DEFAULT_VERIFIER_BYTES): String {
        require(entropyBytes in 32..96) {
            "entropyBytes must be between 32 and 96 to stay inside RFC 7636's 43..128 character range"
        }
        return randomUrlSafe(entropyBytes)
    }

    /**
     * `BASE64URL(SHA256(ASCII(verifier)))`, unpadded — the `code_challenge` to send with the
     * authorization request.
     *
     * @throws IllegalArgumentException if [verifier] is not a well-formed RFC 7636 verifier.
     *         Failing here is far better than failing at the token endpoint, where the only
     *         diagnosis available is a flat `invalid_grant`.
     */
    public fun challengeFor(verifier: String): String {
        require(UNRESERVED.matches(verifier)) {
            "code verifier must be 43..128 characters from the unreserved set [A-Za-z0-9-._~]"
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    /**
     * A matched verifier/challenge pair, generated together so the two cannot drift apart.
     *
     * @return the pair to use for one authorization request. Never reuse a pair.
     */
    public fun generate(): PkcePair {
        val verifier = generateVerifier()
        return PkcePair(verifier = verifier, challenge = challengeFor(verifier), method = "S256")
    }

    /**
     * An opaque, single-use `state` value.
     *
     * Not strictly PKCE, but it belongs to the same hop: `state` binds the callback to the
     * request that started it and is the CSRF defence for the authorization code flow. PKCE does
     * not replace it.
     *
     * Deliberately *not* built through [generateVerifier]: `state` is not a code verifier and is
     * not bound by RFC 7636's 43–128 character range, so borrowing that check here only ever
     * rejected sizes the specification never applied to.
     */
    public fun generateState(): String = randomUrlSafe(OPAQUE_VALUE_BYTES)

    /**
     * An opaque, single-use `nonce` for OIDC.
     *
     * Bind it to the user agent, and check that the `nonce` claim in the returned ID token
     * matches. Without it an ID token from a different authorization request can be replayed.
     */
    public fun generateNonce(): String = randomUrlSafe(OPAQUE_VALUE_BYTES)

    /** 192 bits, unpadded base64url — 32 characters. Far past guessing range for a one-shot value. */
    private const val OPAQUE_VALUE_BYTES: Int = 24

    private fun randomUrlSafe(byteCount: Int): String {
        val bytes = ByteArray(byteCount)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

/**
 * A code verifier with its matching challenge.
 *
 * @property verifier the secret half. Keep it on the client that started the flow and send it
 *           only to the token endpoint. It must never appear in a URL, a log line, or a
 *           referrer header.
 * @property challenge the public half, sent as `code_challenge` on the authorization request.
 * @property method always `S256`.
 */
public data class PkcePair(
    public val verifier: String,
    public val challenge: String,
    public val method: String,
) {
    /** Redacted: a `toString()` that leaks the verifier into a log is the usual way it escapes. */
    override fun toString(): String = "PkcePair(challenge=$challenge, method=$method, verifier=***)"
}
