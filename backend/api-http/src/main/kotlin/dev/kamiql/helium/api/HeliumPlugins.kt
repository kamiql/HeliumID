package dev.kamiql.helium.api

import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.error.AuthErrorException
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.callid.CallId
import io.ktor.server.plugins.callid.callIdMdc
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.plugins.defaultheaders.DefaultHeaders
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.serialization.json.Json
import org.slf4j.event.Level

/**
 * Installs the Ktor plugins HeliumID needs, in the order they must run.
 *
 * `CallId` first so every later plugin — logging, error mapping — can attach the correlation
 * id; `StatusPages` before routing so nothing escapes as a stack trace.
 */
fun Application.installHeliumPlugins(config: HttpSecurityConfig) {

    install(CallId) {
        // Accept a caller-supplied id so a request can be traced across services, but only if
        // it is short and alphanumeric: this value ends up in logs and in the audit table.
        retrieveFromHeader(HttpHeaders.XRequestId)
        verify { it.length in 1..128 && it.all { char -> char.isLetterOrDigit() || char in "-_" } }
        generate { "req_" + java.util.UUID.randomUUID().toString().replace("-", "").take(24) }
        replyToHeader(HttpHeaders.XRequestId)
    }

    install(CallLogging) {
        level = Level.INFO
        callIdMdc("request_id")
        // Health and metrics would otherwise dominate the log volume. Both are polled on a
        // fixed interval by infrastructure, so every line they produce is noise.
        filter { call ->
            val uri = call.request.local.uri
            !uri.startsWith("/health") && !uri.startsWith("/metrics")
        }
        format { call ->
            // Deliberately minimal and structured. Concept §7.5: no cookies, no tokens, no
            // query strings — an authorization code or a reset token lives in a query string.
            "${call.request.local.method.value} ${call.request.path()} -> ${call.response.status()?.value}"
        }
    }

    install(DefaultHeaders) {
        // This service serves JSON and redirects, never HTML it wants embedded elsewhere.
        header("X-Content-Type-Options", "nosniff")
        header("X-Frame-Options", "DENY")
        header("Referrer-Policy", "no-referrer")
        header("Cross-Origin-Opener-Policy", "same-origin")
        header("Cross-Origin-Resource-Policy", "same-origin")
        if (config.secureCookies) {
            // Only meaningful over HTTPS, and actively harmful to set during local dev.
            header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        }
    }

    install(ContentNegotiation) {
        json(
            Json {
                // Absent optional fields are omitted rather than serialized as null, which
                // keeps the wire format stable as DTOs gain fields.
                explicitNulls = false
                ignoreUnknownKeys = true
                encodeDefaults = true
            },
        )
    }

    /**
     * Explicit CORS allowlist (concept §7.4).
     *
     * `allowCredentials` is on because the SPA authenticates with a cookie, which is exactly
     * why the origin list must be exact — a wildcard here would let any site drive the API as
     * the signed-in user.
     */
    install(CORS) {
        config.allowedOrigins.forEach { origin ->
            val withoutScheme = origin.substringAfter("://")
            val scheme = origin.substringBefore("://")
            allowHost(withoutScheme, schemes = listOf(scheme))
        }
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Patch)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(CSRF_HEADER)
        allowHeader("Idempotency-Key")
        allowHeader(HttpHeaders.XRequestId)
        exposeHeader(HttpHeaders.XRequestId)
        exposeHeader(HttpHeaders.RetryAfter)
        allowCredentials = true
        maxAgeInSeconds = 600
    }

    /**
     * Every error leaves through here as problem+json.
     *
     * Nothing else in the codebase writes an error body, so there is one place to audit for
     * information disclosure.
     */
    install(StatusPages) {
        exception<AuthErrorException> { call, cause ->
            call.respondProblem(cause.error)
        }

        exception<BadRequestException> { call, _ ->
            // Malformed JSON or a missing field. The parser's message can echo the payload, so
            // it is never forwarded.
            call.respondProblem(AuthError.ValidationFailed(mapOf("body" to "malformed")))
        }

        exception<kotlinx.serialization.SerializationException> { call, _ ->
            call.respondProblem(AuthError.ValidationFailed(mapOf("body" to "malformed")))
        }

        exception<Throwable> { call, cause ->
            // Log with the correlation id; return nothing but the id. An internal error message
            // is a gift to an attacker mapping the system.
            call.application.log.error("unhandled error on {}", call.request.local.uri, cause)
            call.respondProblem(AuthError.TemporarilyUnavailable)
        }

        status(HttpStatusCode.NotFound) { call, _ ->
            call.respondProblem(AuthError.NotFound)
        }

        status(HttpStatusCode.MethodNotAllowed) { call, _ ->
            call.respond(HttpStatusCode.MethodNotAllowed)
        }
    }
}

/**
 * Liveness and readiness.
 *
 * Unauthenticated and deliberately uninformative: a health endpoint that reports which
 * dependency is down is a reconnaissance endpoint. The detail belongs in metrics and logs.
 */
fun Application.installHealthRoutes(readiness: suspend () -> Boolean) {
    routing {
        get("/health") {
            call.respondText("ok", ContentType.Text.Plain)
        }
        get("/health/ready") {
            if (readiness()) {
                call.respondText("ready", ContentType.Text.Plain)
            } else {
                call.respondText("not ready", ContentType.Text.Plain, HttpStatusCode.ServiceUnavailable)
            }
        }
    }
}

/**
 * Prometheus scrape endpoint.
 *
 * Unauthenticated, like `/health`, and for the same reason it is *not* harmless: the counters
 * name login volumes, failure rates and client ids. Exposure is controlled at the edge —
 * `infra/Caddyfile.dev` proxies it, `infra/Caddyfile.prod` does not — because an authentication
 * scheme here would have to be one more credential to rotate, and the scraper already lives on
 * the internal network.
 */
fun Application.installMetricsRoute(metrics: MetricsEndpoint) {
    routing {
        get("/metrics") {
            call.respondText(metrics.scrape(), ContentType.parse(metrics.contentType))
        }
    }
}

private fun io.ktor.server.request.ApplicationRequest.path(): String = local.uri.substringBefore('?')
