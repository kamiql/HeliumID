package dev.kamiql.helium.oauth

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import java.time.Instant

/**
 * Commands and results for the protocol endpoints.
 *
 * These mirror the wire format closely on purpose: the OAuth specification is the contract,
 * and a "nicer" internal shape would only make it harder to check the implementation against
 * the RFC.
 */

/**
 * `GET /oauth2/authorize`.
 *
 * @param sessionId the browser session, if any. Absent means the user must sign in first; the
 *        endpoint responds with a redirect to the login UI rather than an error.
 */
data class AuthorizeCommand(
    val clientId: String,
    val responseType: String,
    val redirectUri: String,
    val scope: String,
    val state: String?,
    val nonce: String?,
    val codeChallenge: String?,
    val codeChallengeMethod: String?,
    val prompt: String?,
    val sessionId: SessionId?,
    /** Set once the user has approved the consent screen in this request cycle. */
    val consentGranted: Boolean = false,
)

sealed interface AuthorizeResult {

    /** Success: send the browser back to the client with the code. */
    data class Redirect(val location: String) : AuthorizeResult

    /** The user is not signed in, or `prompt=login` demanded a fresh sign-in. */
    data class LoginRequired(val returnTo: String) : AuthorizeResult

    /**
     * The user must approve scopes.
     *
     * @param scopes the scopes needing approval, with their human descriptions.
     */
    data class ConsentRequired(
        val clientName: String,
        val clientId: ClientId,
        val scopes: List<ConsentScope>,
        val returnTo: String,
    ) : AuthorizeResult
}

data class ConsentScope(val name: String, val description: String)

/**
 * `POST /oauth2/token`.
 *
 * @param clientSecret present only for confidential clients; public clients authenticate with
 *        PKCE alone.
 * @param codeVerifier the PKCE verifier for the `authorization_code` grant.
 */
data class TokenCommand(
    val grantType: String,
    val code: String? = null,
    val redirectUri: String? = null,
    val codeVerifier: Secret? = null,
    val refreshToken: Secret? = null,
    val scope: String? = null,
    val clientId: String? = null,
    val clientSecret: Secret? = null,
)

data class TokenResponse(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long,
    val refreshToken: String?,
    val idToken: String?,
    val scope: String,
)

/** `POST /oauth2/revoke` (RFC 7009). */
data class RevokeCommand(
    val token: Secret,
    val tokenTypeHint: String?,
    val clientId: String?,
    val clientSecret: Secret?,
)

/** `POST /oauth2/introspect` (RFC 7662). */
data class IntrospectCommand(
    val token: Secret,
    val clientId: String?,
    val clientSecret: Secret?,
)

/**
 * RFC 7662 introspection response.
 *
 * When `active` is false every other field must be absent: reporting the subject or expiry of
 * an inactive token leaks information about tokens the caller does not hold.
 */
data class IntrospectionResponse(
    val active: Boolean,
    val scope: String? = null,
    val clientId: String? = null,
    val username: String? = null,
    val tokenType: String? = null,
    val exp: Long? = null,
    val iat: Long? = null,
    val sub: String? = null,
    val aud: List<String>? = null,
    val iss: String? = null,
    val jti: String? = null,
) {
    companion object {
        val INACTIVE: IntrospectionResponse = IntrospectionResponse(active = false)
    }
}

/** `GET /userinfo`. */
data class UserInfoResponse(
    val sub: String,
    val name: String?,
    val preferredUsername: String?,
    val givenName: String?,
    val familyName: String?,
    val email: String?,
    val emailVerified: Boolean?,
    val updatedAt: Long?,
)

// --- client administration -----------------------------------------------------

data class RegisterClientCommand(
    val clientId: String,
    val name: String,
    val type: ClientType,
    val redirectUris: Set<String>,
    val scopes: Set<String>,
    val grantTypes: Set<GrantType>,
    val audiences: Set<String>,
    val skipConsent: Boolean,
)

data class UpdateClientCommand(
    val clientId: ClientId,
    val name: String?,
    val redirectUris: Set<String>?,
    val scopes: Set<String>?,
    val grantTypes: Set<GrantType>?,
    val audiences: Set<String>?,
    val skipConsent: Boolean?,
    val enabled: Boolean?,
)

data class RotateClientSecretCommand(val clientId: ClientId)

/**
 * A client secret, returned exactly once.
 *
 * `null` for public clients. There is no endpoint that can show it again — rotation issues a
 * new one, which is the only recovery path.
 */
data class ClientSecretIssued(
    val clientId: ClientId,
    val secret: String?,
    val rotatedAt: Instant,
)

data class DeleteClientCommand(val clientId: ClientId)

/** Result of the consent decision flow. */
data class GrantConsentCommand(
    val clientId: ClientId,
    val scopes: Set<String>,
)

data class RevokeConsentCommand(val clientId: ClientId)

/** Internal: everything an authorization decision needs, resolved once. */
internal data class AuthorizationSubject(
    val userId: UserId,
    val sessionId: SessionId?,
    val authenticatedAt: Instant,
    val methods: Set<dev.kamiql.helium.domain.session.AuthenticationMethod>,
)
