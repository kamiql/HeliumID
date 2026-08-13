package dev.kamiql.helium.api

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.repository.RoleRepository
import dev.kamiql.helium.domain.repository.RevokedTokenRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.identity.SessionService
import dev.kamiql.helium.oauth.TokenIssuer
import io.ktor.http.CookieEncoding
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.util.url
import java.time.Instant

/**
 * Browser-facing security settings.
 *
 * @param secureCookies must be `true` anywhere but local development. `false` also drops the
 *        `__Host-` prefix, because that prefix *requires* `Secure` and a browser silently
 *        ignores a cookie that claims one without the other.
 * @param trustForwardedHeaders only enable behind a proxy you control. Trusting
 *        `X-Forwarded-For` from the open internet lets any caller forge the IP every
 *        rate limit is keyed on (concept §6.1).
 */
data class HttpSecurityConfig(
    val issuerUrl: String,
    val allowedOrigins: Set<String>,
    val secureCookies: Boolean = true,
    val sameSite: String = "Lax",
    val trustForwardedHeaders: Boolean = false,
    val sessionCookieName: String = if (secureCookies) "__Host-helium_session" else "helium_session",
    val csrfCookieName: String = if (secureCookies) "__Host-helium_csrf" else "helium_csrf",
    val providerStateCookieName: String = if (secureCookies) "__Host-helium_pstate" else "helium_pstate",
    val trustedDeviceCookieName: String = if (secureCookies) "__Host-helium_tdevice" else "helium_tdevice",
) {
    init {
        require(allowedOrigins.none { it == "*" }) {
            // Concept §7.4: a wildcard origin with credentials is rejected by browsers and is
            // a mistake even where it is not.
            "CORS origins must be an explicit allowlist"
        }
        if (secureCookies) {
            require(sessionCookieName.startsWith("__Host-")) {
                "secure deployments must use the __Host- cookie prefix"
            }
        }
    }
}

/**
 * Sets the session cookie.
 *
 * `__Host-` prefix rules (concept §4.4): `Secure`, no `Domain`, `Path=/`. The browser enforces
 * them, which is exactly why the prefix is worth using — a misconfiguration becomes a cookie
 * the browser refuses rather than a subtly weaker cookie it accepts.
 */
fun ApplicationCall.setSessionCookie(config: HttpSecurityConfig, value: String, maxAgeSeconds: Long) {
    response.cookies.append(
        name = config.sessionCookieName,
        value = value,
        encoding = CookieEncoding.RAW,
        maxAge = maxAgeSeconds,
        path = "/",
        secure = config.secureCookies,
        httpOnly = true,
        extensions = mapOf("SameSite" to config.sameSite),
    )
}

fun ApplicationCall.clearSessionCookie(config: HttpSecurityConfig) {
    response.cookies.append(
        name = config.sessionCookieName,
        value = "",
        encoding = CookieEncoding.RAW,
        maxAge = 0,
        path = "/",
        secure = config.secureCookies,
        httpOnly = true,
        extensions = mapOf("SameSite" to config.sameSite),
    )
}

/**
 * Sets the trusted-device cookie.
 *
 * `HttpOnly` even though the SPA drives the "remember this device" checkbox: the checkbox is an
 * input to the flow, the cookie is the resulting credential, and nothing in the page ever needs
 * to read it back. Leaving it script-readable would mean an XSS could lift a value that skips the
 * second factor on the *next* login — a credential that survives the session it was stolen from.
 *
 * @param maxAgeSeconds should track the device record's absolute expiry. The server would reject
 *        a stale cookie anyway, but a browser that keeps sending one turns every subsequent login
 *        into a lookup that can only fail.
 */
fun ApplicationCall.setTrustedDeviceCookie(config: HttpSecurityConfig, value: String, maxAgeSeconds: Long) {
    response.cookies.append(
        name = config.trustedDeviceCookieName,
        value = value,
        encoding = CookieEncoding.RAW,
        maxAge = maxAgeSeconds,
        path = "/",
        secure = config.secureCookies,
        httpOnly = true,
        extensions = mapOf("SameSite" to config.sameSite),
    )
}

/**
 * Deletes the trusted-device cookie.
 *
 * Worth doing eagerly whenever the server-side record is gone. The value is inert once the record
 * is revoked, but a browser that keeps offering it is still shipping a dead credential on every
 * request to this origin, and a user who asked to be forgotten is entitled to see it disappear.
 */
fun ApplicationCall.clearTrustedDeviceCookie(config: HttpSecurityConfig) {
    response.cookies.append(
        name = config.trustedDeviceCookieName,
        value = "",
        encoding = CookieEncoding.RAW,
        maxAge = 0,
        path = "/",
        secure = config.secureCookies,
        httpOnly = true,
        extensions = mapOf("SameSite" to config.sameSite),
    )
}

/**
 * Issues the CSRF token cookie.
 *
 * Deliberately **not** `HttpOnly`: the SPA has to read it to echo it back in the
 * `X-CSRF-Token` header. That is the double-submit pattern, and the token's only job is to be
 * unreadable by a *different* origin — which the same-origin policy guarantees.
 */
fun ApplicationCall.setCsrfCookie(config: HttpSecurityConfig, value: String) {
    response.cookies.append(
        name = config.csrfCookieName,
        value = value,
        encoding = CookieEncoding.RAW,
        path = "/",
        secure = config.secureCookies,
        httpOnly = false,
        extensions = mapOf("SameSite" to config.sameSite),
    )
}

/**
 * Layered CSRF defence for cookie-authenticated state changes (concept §4.5).
 *
 * Four independent checks, because each has a known bypass on its own:
 *
 *  * `SameSite` is set on the cookie, but older browsers and some embedded webviews ignore it;
 *  * `Origin` is reliable on modern browsers but absent on some same-origin requests;
 *  * `Sec-Fetch-Site` is strong but not universally supported;
 *  * the double-submit token works even when every header is missing.
 *
 * A request must pass the token check; the header checks reject earlier and more cheaply.
 *
 * @return `null` when the request may proceed, or the error to respond with.
 */
fun ApplicationCall.checkCsrf(config: HttpSecurityConfig): AuthError? {
    // Safe methods do not change state, so they need no token.
    if (request.httpMethod in SAFE_METHODS) return null

    // Bearer-authenticated APIs are not vulnerable to cookie CSRF: the browser will not attach
    // an Authorization header cross-site.
    if (request.header(HttpHeaders.Authorization) != null) return null

    request.header("Sec-Fetch-Site")?.let { site ->
        if (site !in ALLOWED_FETCH_SITES) {
            return AuthError.Forbidden("csrf:sec-fetch-site")
        }
    }

    request.header(HttpHeaders.Origin)?.let { origin ->
        if (origin !in config.allowedOrigins && origin != config.issuerUrl.trimEnd('/')) {
            return AuthError.Forbidden("csrf:origin")
        }
    }

    val cookieToken = request.cookies[config.csrfCookieName]
    val headerToken = request.header(CSRF_HEADER)
    if (cookieToken.isNullOrBlank() || headerToken.isNullOrBlank()) {
        return AuthError.Forbidden("csrf:token-missing")
    }
    if (!java.security.MessageDigest.isEqual(
            cookieToken.toByteArray(Charsets.UTF_8),
            headerToken.toByteArray(Charsets.UTF_8),
        )
    ) {
        return AuthError.Forbidden("csrf:token-mismatch")
    }
    return null
}

const val CSRF_HEADER: String = "X-CSRF-Token"

private val SAFE_METHODS = setOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options)
private val ALLOWED_FETCH_SITES = setOf("same-origin", "same-site", "none")

/**
 * Resolves the caller into a [Principal].
 *
 * Two credential shapes are accepted and they are kept distinct all the way through:
 * a browser session cookie produces [Principal.UserSession], a bearer token produces
 * [Principal.TokenBearer] or [Principal.ServiceClient]. Collapsing them would lose the
 * information that step-up requirements depend on.
 */
class PrincipalResolver(
    private val config: HttpSecurityConfig,
    private val sessionService: SessionService,
    private val users: UserRepository,
    private val roles: RoleRepository,
    private val tokenIssuer: TokenIssuer,
    private val revokedTokens: RevokedTokenRepository,
) {

    suspend fun resolve(call: ApplicationCall, now: Instant): Principal {
        call.request.header(HttpHeaders.Authorization)
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?.removePrefix("bearer ")
            ?.trim()
            ?.let { token -> return resolveBearer(token, now) }

        val cookie = call.request.cookies[config.sessionCookieName] ?: return Principal.Anonymous
        val session = sessionService.resolve(cookie, now) ?: return Principal.Anonymous
        val user = users.findById(session.userId) ?: return Principal.Anonymous
        if (user.toAccessError() != null) return Principal.Anonymous

        return Principal.UserSession(
            userId = user.id,
            sessionId = session.id,
            permissions = roles.permissionsOf(user.id),
            roles = roles.rolesOf(user.id),
            authenticationMethods = session.authenticationMethods,
            emailVerified = user.isEmailVerified,
        )
    }

    private suspend fun resolveBearer(token: String, now: Instant): Principal {
        val verified = tokenIssuer.verify(token, now = now) ?: return Principal.Anonymous
        // Signature and expiry are not enough: an explicitly revoked token must stop working
        // before it expires, which is the whole reason the deny list exists.
        if (revokedTokens.isRevoked(verified.tokenId)) return Principal.Anonymous

        val userId = verified.userId
        val clientId = verified.clientId ?: return Principal.Anonymous

        if (userId == null) {
            return Principal.ServiceClient(
                clientId = clientId,
                scopes = verified.scopes,
                // Machine principals get no user permissions; scopes are their only authority.
                permissions = emptySet(),
            )
        }

        val user = users.findById(userId) ?: return Principal.Anonymous
        if (user.toAccessError() != null) return Principal.Anonymous

        return Principal.TokenBearer(
            userId = userId,
            clientId = clientId,
            scopes = verified.scopes,
            permissions = roles.permissionsOf(userId),
            authenticationMethods = verified.authenticationMethods,
        )
    }
}

/**
 * Builds the [FlowContext] for one request.
 *
 * `now` is captured once here and used by every expiry check in the flow, so a single request
 * cannot observe two different "current" times.
 */
fun ApplicationCall.toFlowContext(
    actor: Principal,
    now: Instant,
    config: HttpSecurityConfig,
    clientId: ClientId? = null,
): FlowContext = FlowContext(
    requestId = RequestId(correlationId ?: "unknown"),
    actor = actor,
    clientId = clientId,
    ipAddress = clientIpAddress(config),
    userAgent = request.header(HttpHeaders.UserAgent)?.take(512),
    idempotencyKey = request.header("Idempotency-Key")?.take(255),
    now = now,
    origin = request.header(HttpHeaders.Origin),
)

/**
 * The caller's IP.
 *
 * `X-Forwarded-For` is only consulted when the deployment declares it is behind a trusted
 * proxy. Otherwise the socket address is used, because a forged header would let a single
 * attacker present a fresh IP for every login attempt and walk straight through the per-IP
 * rate limits.
 */
private fun ApplicationCall.clientIpAddress(config: HttpSecurityConfig): String? =
    if (config.trustForwardedHeaders) {
        request.header(HttpHeaders.XForwardedFor)
            ?.split(',')
            // Left-most entry is the original client; the proxy appends its own peers.
            ?.firstOrNull()
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?: request.origin.remoteHost
    } else {
        request.origin.remoteHost
    }

/** Generates a fresh CSRF token. */
fun newCsrfToken(random: RandomSource): String = random.token(24)

/** Reads a form or query value as a [Secret] so it cannot be logged by accident. */
fun String?.asSecret(): Secret? = this?.takeIf { it.isNotEmpty() }?.let(Secret::of)

/** Absolute URL of the current request, for building return-to links. */
fun ApplicationCall.absoluteUrl(): String = url()
