package dev.kamiql.helium.api

import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.flow.FlowResult
import dev.kamiql.helium.oauth.AuthorizeCommand
import dev.kamiql.helium.oauth.AuthorizeResult
import dev.kamiql.helium.oauth.DiscoveryMetadata
import dev.kamiql.helium.oauth.IntrospectCommand
import dev.kamiql.helium.oauth.RevokeCommand
import dev.kamiql.helium.oauth.TokenCommand
import dev.kamiql.helium.oauth.buildUserInfo
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.header
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import java.util.Base64

/**
 * The `.well-known` documents — metadata every client reads before it talks to anything else.
 *
 * Both documents are public, unauthenticated and cacheable. JWKS in particular must be
 * cacheable: verifiers fetch it constantly, and the key-rotation overlap window exists
 * precisely so their caches stay valid.
 */
fun Route.discoveryRoutes(dependencies: HeliumApiDependencies) {

    get("/.well-known/openid-configuration") {
        val scopes = dependencies.clients.listScopes().map { it.name }.sorted()
        val metadata = DiscoveryMetadata.forIssuer(dependencies.config.issuerUrl, scopes)
        call.response.header(HttpHeaders.CacheControl, "public, max-age=300")
        call.respond(metadata.toDto())
    }

    get("/.well-known/jwks.json") {
        call.response.header(HttpHeaders.CacheControl, "public, max-age=600")
        call.respondText(dependencies.signingKeys.jwks(), ContentType.Application.Json)
    }
}

/**
 * The OAuth 2 / OIDC endpoints (concept §5.1).
 *
 * These use RFC 6749's error shape rather than problem+json — see [toOAuthError]. Mixing the
 * two would break conforming OAuth clients, which parse `error` and nothing else.
 */
fun Route.oauthRoutes(dependencies: HeliumApiDependencies) = route("/oauth2") {

    /**
     * The authorization endpoint.
     *
     * Three outcomes: redirect with a code, redirect to login, or return a consent prompt for
     * the built-in UI to render.
     */
    get("/authorize") {
        val params = call.request.queryParameters
        val (actor, context) = call.heliumContext(dependencies)

        val command = AuthorizeCommand(
            clientId = params["client_id"].orEmpty(),
            responseType = params["response_type"].orEmpty(),
            redirectUri = params["redirect_uri"].orEmpty(),
            scope = params["scope"].orEmpty(),
            state = params["state"],
            nonce = params["nonce"],
            codeChallenge = params["code_challenge"],
            codeChallengeMethod = params["code_challenge_method"],
            prompt = params["prompt"],
            sessionId = (actor as? Principal.UserSession)?.sessionId,
            consentGranted = params["consent"] == "granted",
        )

        when (val result = dependencies.flowRunner.execute(dependencies.oauthFlows.authorize, command, context)) {
            is FlowResult.Success -> when (val outcome = result.value) {
                is AuthorizeResult.Redirect -> call.respondRedirect(outcome.location)

                is AuthorizeResult.LoginRequired ->
                    // The login UI is a front-end route; it sends the user back to `returnTo`
                    // after authenticating.
                    call.respondRedirect("/login?return_to=${encodeQuery(outcome.returnTo)}")

                is AuthorizeResult.ConsentRequired -> call.respond(
                    ConsentPromptResponse(
                        clientId = outcome.clientId.value,
                        clientName = outcome.clientName,
                        scopes = outcome.scopes.map { ScopeDescriptionDto(it.name, it.description) },
                        returnTo = outcome.returnTo,
                    ),
                )
            }

            is FlowResult.Failure ->
                // Errors are never redirected: by the time we know the redirect URI is valid we
                // have already succeeded, and reporting to an unvalidated URI is an open
                // redirect (concept §4.9).
                call.respondProblem(result.error)

            is FlowResult.Challenge -> call.respondProblem(
                AuthError.MfaRequired(result.transactionId, result.methods, result.expiresAt),
            )
        }
    }

    post("/token") {
        val form = call.receiveParameters()
        val basic = call.basicClientCredentials()

        val command = TokenCommand(
            grantType = form["grant_type"].orEmpty(),
            code = form["code"],
            redirectUri = form["redirect_uri"],
            codeVerifier = form["code_verifier"].asSecret(),
            refreshToken = form["refresh_token"].asSecret(),
            scope = form["scope"],
            // `client_secret_basic` takes precedence over `client_secret_post`, per RFC 6749
            // §2.3.1's preference for the Authorization header.
            clientId = basic?.first ?: form["client_id"],
            clientSecret = basic?.second ?: form["client_secret"].asSecret(),
        )

        val clientId = command.clientId?.let { runCatching { ClientId(it) }.getOrNull() }
        val (_, context) = call.heliumContext(dependencies, clientId)
        val result = dependencies.flowRunner.execute(dependencies.oauthFlows.token, command, context)

        // Token responses must never be cached anywhere (RFC 6749 §5.1).
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.response.header(HttpHeaders.Pragma, "no-cache")

        when (result) {
            is FlowResult.Success -> call.respond(
                TokenEndpointResponse(
                    accessToken = result.value.accessToken,
                    tokenType = result.value.tokenType,
                    expiresIn = result.value.expiresIn,
                    refreshToken = result.value.refreshToken,
                    idToken = result.value.idToken,
                    scope = result.value.scope,
                ),
            )
            is FlowResult.Failure -> call.respond(result.error.toOAuthStatus(), result.error.toOAuthError())
            is FlowResult.Challenge -> call.respond(
                HttpStatusCode.BadRequest,
                OAuthErrorResponse("invalid_grant", "additional authentication required"),
            )
        }
    }

    /** RFC 7009. Always `200`, so it cannot be used to test whether a token is valid. */
    post("/revoke") {
        val form = call.receiveParameters()
        val basic = call.basicClientCredentials()
        val token = form["token"].asSecret()
        if (token == null) {
            call.respond(HttpStatusCode.BadRequest, OAuthErrorResponse("invalid_request", "token is required"))
            return@post
        }

        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.oauthFlows.revoke,
            command = RevokeCommand(
                token = token,
                tokenTypeHint = form["token_type_hint"],
                clientId = basic?.first ?: form["client_id"],
                clientSecret = basic?.second ?: form["client_secret"].asSecret(),
            ),
            context = context,
        )
        when (result) {
            is FlowResult.Failure -> call.respond(result.error.toOAuthStatus(), result.error.toOAuthError())
            else -> call.respond(HttpStatusCode.OK)
        }
    }

    /** RFC 7662. Requires client authentication: this endpoint reads other people's tokens. */
    post("/introspect") {
        val form = call.receiveParameters()
        val basic = call.basicClientCredentials()
        val token = form["token"].asSecret()
        if (token == null) {
            call.respond(HttpStatusCode.BadRequest, OAuthErrorResponse("invalid_request", "token is required"))
            return@post
        }

        val response = dependencies.oauthFlows.introspect(
            command = IntrospectCommand(
                token = token,
                clientId = basic?.first ?: form["client_id"],
                clientSecret = basic?.second ?: form["client_secret"].asSecret(),
            ),
            now = dependencies.clock.now(),
        )
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.respond(
            IntrospectionResponseDto(
                active = response.active,
                scope = response.scope,
                clientId = response.clientId,
                username = response.username,
                tokenType = response.tokenType,
                exp = response.exp,
                iat = response.iat,
                sub = response.sub,
                aud = response.aud,
                iss = response.iss,
                jti = response.jti,
            ),
        )
    }
}

/**
 * `GET /userinfo` (OIDC Core §5.3).
 *
 * Bearer only, and the claims returned are gated on the token's scopes.
 */
fun Route.userInfoRoute(dependencies: HeliumApiDependencies) {
    get("/userinfo") {
        val (actor, _) = call.heliumContext(dependencies)
        val (userId, scopes) = when (actor) {
            is Principal.TokenBearer -> actor.userId to actor.scopes
            // A cookie session is not a bearer token; OIDC clients must present the token they
            // were issued.
            else -> {
                call.respondProblem(AuthError.AuthenticationRequired)
                return@get
            }
        }
        if (Scope.OPENID !in scopes) {
            call.respondProblem(AuthError.Forbidden("scope:openid"))
            return@get
        }
        val user = dependencies.users.findById(userId)
        if (user == null) {
            call.respondProblem(AuthError.AuthenticationRequired)
            return@get
        }
        val info = buildUserInfo(user, scopes)
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.respond(
            UserInfoDto(
                sub = info.sub,
                name = info.name,
                preferredUsername = info.preferredUsername,
                givenName = info.givenName,
                familyName = info.familyName,
                email = info.email,
                emailVerified = info.emailVerified,
                updatedAt = info.updatedAt,
            ),
        )
    }
}

/**
 * Parses `Authorization: Basic` client credentials (RFC 6749 §2.3.1).
 *
 * Both halves are form-urldecoded, which the RFC requires and which implementations routinely
 * forget — a secret containing `+` or `%` fails to authenticate otherwise.
 */
private fun ApplicationCall.basicClientCredentials(): Pair<String, dev.kamiql.helium.domain.common.Secret>? {
    val header = request.header(HttpHeaders.Authorization) ?: return null
    if (!header.startsWith("Basic ", ignoreCase = true)) return null
    val decoded = runCatching {
        String(Base64.getDecoder().decode(header.removePrefix("Basic ").removePrefix("basic ").trim()))
    }.getOrNull() ?: return null
    val separator = decoded.indexOf(':')
    if (separator <= 0) return null
    val clientId = java.net.URLDecoder.decode(decoded.substring(0, separator), Charsets.UTF_8)
    val secret = java.net.URLDecoder.decode(decoded.substring(separator + 1), Charsets.UTF_8)
    return clientId to dev.kamiql.helium.domain.common.Secret.of(secret)
}

private fun encodeQuery(value: String): String = java.net.URLEncoder.encode(value, Charsets.UTF_8)

private fun DiscoveryMetadata.toDto(): DiscoveryResponse = DiscoveryResponse(
    issuer = issuer,
    authorizationEndpoint = authorizationEndpoint,
    tokenEndpoint = tokenEndpoint,
    userinfoEndpoint = userinfoEndpoint,
    jwksUri = jwksUri,
    revocationEndpoint = revocationEndpoint,
    introspectionEndpoint = introspectionEndpoint,
    endSessionEndpoint = endSessionEndpoint,
    scopesSupported = scopesSupported,
    responseTypesSupported = responseTypesSupported,
    grantTypesSupported = grantTypesSupported,
    subjectTypesSupported = subjectTypesSupported,
    idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported,
    tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported,
    codeChallengeMethodsSupported = codeChallengeMethodsSupported,
    claimsSupported = claimsSupported,
)
