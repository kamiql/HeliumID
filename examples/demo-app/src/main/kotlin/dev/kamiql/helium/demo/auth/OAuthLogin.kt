package dev.kamiql.helium.demo.auth

import dev.kamiql.helium.client.HeliumApiException
import dev.kamiql.helium.client.HeliumIdClient
import dev.kamiql.helium.client.Pkce
import dev.kamiql.helium.demo.DemoConfig
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.sessions.clear
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger("dev.kamiql.helium.demo.auth")

/** Name of the short-lived cookie holding the pending login's handle. */
const val LOGIN_HANDLE_COOKIE: String = "demo_login"

/**
 * Authorization Code with PKCE, the only interactive flow HeliumID accepts.
 *
 * Three routes and one rule: the authorization code and both tokens exist only on this server.
 * The browser sees a redirect, a callback, and afterwards an opaque session cookie.
 */
fun Route.oauthLoginRoutes(
    config: DemoConfig,
    client: HeliumIdClient,
    sessions: SessionStore,
    idTokens: IdTokenVerifier,
) {

    /**
     * Sends the user to HeliumID.
     *
     * `state`, `nonce` and the PKCE verifier are generated here and kept server-side. All three
     * matter, and two of them are the client's job whatever the server does: HeliumID accepts an
     * authorization request without `state` or `nonce` and never checks either, so a relying
     * party that omits them simply has no CSRF protection on the callback and no replay
     * protection on the ID token.
     */
    get("/login") {
        if (sessions.find(call.sessions.get<SessionCookie>()?.id) != null) {
            call.respondRedirect("/")
            return@get
        }

        // Only a local path, and never one supplied verbatim. Reflecting an absolute URL here
        // would make this endpoint an open redirect.
        val returnTo = call.request.queryParameters["return_to"]
            ?.takeIf { it.startsWith("/") && !it.startsWith("//") }
            ?: "/"

        val (handle, transaction) = sessions.beginLogin(returnTo)
        call.setLoginHandle(handle)

        call.respondRedirect(
            client.authorizationUrl(
                clientId = config.clientId,
                redirectUri = config.redirectUri,
                scope = config.scopes,
                state = transaction.state,
                codeChallenge = Pkce.challengeFor(transaction.codeVerifier),
                nonce = transaction.nonce,
            ),
        )
    }

    /**
     * Where HeliumID sends the browser back.
     *
     * Every failure below ends the attempt rather than repairing it. A callback that cannot be
     * tied to a request this application started is not a login worth rescuing.
     */
    get("/callback") {
        val transaction = sessions.consumeLogin(call.consumeLoginHandle())
        if (transaction == null) {
            // No pending login, or one already used, or one that expired. Indistinguishable on
            // purpose — all three mean "start again".
            call.respondRedirect("/?error=no_pending_login")
            return@get
        }

        // Errors arrive as query parameters only from a conforming provider; HeliumID reports
        // authorization failures as problem+json instead. Handled anyway: the callback must not
        // assume the happy shape.
        call.request.queryParameters["error"]?.let { error ->
            log.info("authorization refused: {}", error)
            call.respondRedirect("/?error=authorization_refused")
            return@get
        }

        val state = call.request.queryParameters["state"]
        if (state == null || state != transaction.state) {
            // The CSRF defence for the code flow. PKCE does not replace it: PKCE proves the code
            // was requested by this client, `state` proves it was requested for this browser.
            log.warn("state mismatch on callback; dropping the authorization response")
            call.respondRedirect("/?error=state_mismatch")
            return@get
        }

        val code = call.request.queryParameters["code"]
        if (code.isNullOrBlank()) {
            call.respondRedirect("/?error=missing_code")
            return@get
        }

        val tokens = try {
            client.exchangeAuthorizationCode(
                code = code,
                // Byte-identical to the one sent with the authorization request — the token
                // endpoint compares them exactly.
                redirectUri = config.redirectUri,
                clientId = config.clientId,
                codeVerifier = transaction.codeVerifier,
                clientSecret = config.clientSecret,
            )
        } catch (failure: HeliumApiException) {
            log.warn("token exchange failed: {}", failure.error.code)
            call.respondRedirect("/?error=token_exchange_failed")
            return@get
        }

        val idToken = tokens.idToken
        if (idToken == null) {
            // `openid` was requested, so its absence means the grant was not what we asked for.
            call.respondRedirect("/?error=missing_id_token")
            return@get
        }

        val claims = try {
            idTokens.verify(idToken, transaction.nonce)
        } catch (invalid: IdTokenInvalid) {
            log.warn("id token rejected: {}", invalid.message)
            call.respondRedirect("/?error=id_token_invalid")
            return@get
        }

        // Profile, roles and permissions in one call. None of it is in any token — this is the
        // only place a client can learn what the user is allowed to do.
        val user = client.withBearerToken(tokens.accessToken).me()

        val session = sessions.create(tokens, claims.subject, user)
        call.sessions.set(SessionCookie(session.id))
        log.info("signed in {} (acr={})", user.username, claims.authenticationContextClass())

        call.respondRedirect(transaction.returnTo)
    }

    /**
     * Ends the local session and revokes the refresh token.
     *
     * This is *not* RP-initiated OIDC logout: the user stays signed in at HeliumID. The discovery
     * document advertises an `end_session_endpoint` at `{issuer}/oauth2/logout`, but no such route
     * exists — calling it returns 404. Revoking the refresh token is the part that is actually
     * available, and it is the part that matters here: without it this application would keep a
     * usable credential after the user asked it not to.
     */
    post("/logout") {
        val session = sessions.remove(call.sessions.get<SessionCookie>()?.id)
        call.sessions.clear<SessionCookie>()

        session?.refreshToken?.let { token ->
            runCatching {
                client.revoke(
                    token = token,
                    clientId = config.clientId,
                    clientSecret = config.clientSecret,
                    tokenTypeHint = "refresh_token",
                )
            }.onFailure { log.warn("refresh token revocation failed: {}", it.message) }
        }

        call.respondRedirect("/")
    }
}

/**
 * The pending login's handle, in its own short-lived cookie.
 *
 * `SameSite=Lax` rather than `Strict`: the callback arrives as a cross-site top-level navigation
 * from HeliumID, and `Strict` would withhold the cookie exactly then, breaking every login.
 */
private fun ApplicationCall.setLoginHandle(handle: String) {
    response.headers.append(
        "Set-Cookie",
        "$LOGIN_HANDLE_COOKIE=$handle; Path=/; HttpOnly; SameSite=Lax; Max-Age=600",
    )
}

private fun ApplicationCall.consumeLoginHandle(): String? {
    val handle = request.cookies[LOGIN_HANDLE_COOKIE]
    response.headers.append(
        "Set-Cookie",
        "$LOGIN_HANDLE_COOKIE=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
    )
    return handle
}

/** Signs the caller out and reports why, for handlers that find a session beyond saving. */
suspend fun ApplicationCall.endSession(sessions: SessionStore, reason: String) {
    sessions.remove(sessions.find(this.sessions.get<SessionCookie>()?.id)?.id)
    this.sessions.clear<SessionCookie>()
    respondText("Your session has ended ($reason). Sign in again.", status = HttpStatusCode.Unauthorized)
}
