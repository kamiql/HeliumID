package dev.kamiql.helium.domain.token

import dev.kamiql.helium.domain.common.AuthorizationCodeId
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.RefreshTokenFamilyId
import dev.kamiql.helium.domain.common.RefreshTokenId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.session.AuthenticationMethod
import java.time.Instant

/**
 * A chain of refresh tokens descending from one authentication event.
 *
 * The family is the unit of revocation. Presenting an already-used token means either a
 * replay or a stolen token, and neither can be distinguished from the other — so the whole
 * family dies (concept §4.3).
 */
data class RefreshTokenFamily(
    val id: RefreshTokenFamilyId,
    val userId: UserId,
    val clientId: ClientId,
    /** Session that seeded the family, so signing out of a device kills its tokens. */
    val sessionId: SessionId?,
    val scopes: Set<String>,
    val authenticationMethods: Set<AuthenticationMethod>,
    val createdAt: Instant,
    val absoluteExpiresAt: Instant,
    val revokedAt: Instant?,
    val reuseDetectedAt: Instant?,
) {
    fun isActive(now: Instant): Boolean =
        revokedAt == null && reuseDetectedAt == null && now.isBefore(absoluteExpiresAt)
}

/**
 * One link in a [RefreshTokenFamily].
 *
 * Only `HMAC-SHA-256(pepper, token)` is stored (concept §4.3). `usedAt` is set on rotation and
 * is the signal that makes reuse detectable, so used rows are retained until the family
 * expires rather than deleted.
 */
data class RefreshToken(
    val id: RefreshTokenId,
    val familyId: RefreshTokenFamilyId,
    val tokenHash: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val usedAt: Instant?,
    val revokedAt: Instant?,
    val replacedByTokenId: RefreshTokenId?,
) {
    fun isRedeemable(now: Instant): Boolean =
        usedAt == null && revokedAt == null && now.isBefore(expiresAt)
}

/** Outcome of presenting a refresh token, kept explicit so no branch can be forgotten. */
sealed interface RefreshOutcome {
    data class Rotated(val issued: IssuedRefreshToken) : RefreshOutcome

    /** A used token was presented again. The family has been revoked; require full sign-in. */
    data class ReuseDetected(val familyId: RefreshTokenFamilyId, val userId: UserId) : RefreshOutcome

    data object Unknown : RefreshOutcome
    data object Expired : RefreshOutcome
    data object Revoked : RefreshOutcome
}

/** A newly minted refresh token; the plaintext leaves the server exactly once. */
class IssuedRefreshToken(
    val token: RefreshToken,
    val family: RefreshTokenFamily,
    private val plaintext: String,
) {
    fun value(): String = plaintext

    override fun toString(): String = "IssuedRefreshToken(${token.id.value}, redacted)"
}

/**
 * A pending OAuth authorization code.
 *
 * 60-second lifetime, single use, stored as a hash (concept §4.2, §3.2). Everything needed to
 * mint tokens is captured at issue time so the token exchange cannot be influenced by a later
 * change to the client or the session.
 */
data class AuthorizationCode(
    val id: AuthorizationCodeId,
    val codeHash: String,
    val clientId: ClientId,
    val userId: UserId,
    val sessionId: SessionId?,
    /** Must match the token request byte for byte (RFC 6749 §4.1.3). */
    val redirectUri: String,
    val scopes: Set<String>,
    val nonce: String?,
    val codeChallenge: String,
    val codeChallengeMethod: CodeChallengeMethod,
    val authenticationMethods: Set<AuthenticationMethod>,
    val authenticatedAt: Instant,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val consumedAt: Instant?,
) {
    fun isRedeemable(now: Instant): Boolean = consumedAt == null && now.isBefore(expiresAt)
}

/**
 * PKCE transform. Only `S256` is accepted: `plain` offers no protection against an attacker
 * who can already observe the authorization request (CLAUDE.md, concept §5.1).
 */
enum class CodeChallengeMethod {
    S256,
    ;

    companion object {
        fun parse(raw: String?): CodeChallengeMethod? = if (raw == "S256") S256 else null
    }
}

/** Claims carried by an issued access token, before signing. Concept §4.2. */
data class AccessTokenClaims(
    val issuer: String,
    val subject: UserId,
    val audience: List<String>,
    val clientId: ClientId,
    val scopes: Set<String>,
    val authenticationMethods: Set<AuthenticationMethod>,
    /** Authentication context class; `mfa` when a second factor was used, else `pwd`. */
    val acr: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    /** Unique token id, used for revocation checks at the introspection endpoint. */
    val tokenId: String,
    val sessionId: SessionId?,
) {
    init {
        // Concept §4.2: "Do not include unnecessary personal data in access tokens."
        require(audience.isNotEmpty()) { "access token must have an audience" }
    }
}

/** The result of a successful grant: what actually goes back over the wire. */
data class TokenGrant(
    val accessToken: String,
    val accessTokenExpiresAt: Instant,
    val refreshToken: String?,
    val idToken: String?,
    val scopes: Set<String>,
    val tokenType: String = "Bearer",
)
