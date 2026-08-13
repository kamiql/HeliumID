package dev.kamiql.helium.demo

import dev.kamiql.helium.client.HeliumId
import dev.kamiql.helium.client.HeliumIdClient
import dev.kamiql.helium.demo.api.ApiError
import dev.kamiql.helium.demo.api.documentsApi
import dev.kamiql.helium.demo.auth.IdTokenVerifier
import dev.kamiql.helium.demo.auth.SessionCookie
import dev.kamiql.helium.demo.auth.SessionStore
import dev.kamiql.helium.demo.auth.oauthLoginRoutes
import dev.kamiql.helium.demo.domain.Workspace
import dev.kamiql.helium.demo.web.webRoutes
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.cookie
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.slf4j.event.Level
import java.time.Clock
import kotlin.time.Duration.Companion.minutes

private val log = LoggerFactory.getLogger("dev.kamiql.helium.demo")

fun main() {
    val config = DemoConfig.fromEnvironment()

    if (config.clientSecret.isBlank()) {
        System.err.println(
            """
            DEMO_CLIENT_SECRET is not set.

            Register this application with HeliumID first:

                ./gradlew setup

            then export the secret it prints and start again.
            """.trimIndent(),
        )
        kotlin.system.exitProcess(1)
    }

    log.info("issuer {} · redirect {} · audience {}", config.issuer, config.redirectUri, config.audience)

    embeddedServer(Netty, port = config.port, host = "0.0.0.0") {
        demoModule(config)
    }.start(wait = true)
}

fun Application.demoModule(
    config: DemoConfig,
    clock: Clock = Clock.systemUTC(),
    /** Overridable so tests can drive the SDK against a mock engine. */
    client: HeliumIdClient = HeliumIdClient.create(config.issuer),
    /** Overridable so tests can supply a fixed key set instead of fetching JWKS over HTTP. */
    idTokens: IdTokenVerifier = IdTokenVerifier(issuer = config.issuer, clientId = config.clientId),
) {
    val sessions = SessionStore { clock.instant() }
    val workspace = Workspace()

    install(CallLogging) { level = Level.INFO }

    install(ContentNegotiation) {
        json(Json { prettyPrint = true; ignoreUnknownKeys = true })
    }

    /*
     * The browser session cookie carries an opaque id and nothing else — no token, no claims.
     *
     * `httpOnly` keeps it away from scripts, and it is signed so a forged id cannot be presented.
     * `secure` is false only because the dev stack is plain HTTP on localhost; any real
     * deployment must set it, at which point `SameSite=Lax` and the signature are the remaining
     * defences. Lax rather than Strict because the OAuth callback is a cross-site top-level
     * navigation, and Strict would withhold the cookie exactly then.
     */
    install(Sessions) {
        cookie<SessionCookie>("demo_session") {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.extensions["SameSite"] = "Lax"
            cookie.secure = config.baseUrl.startsWith("https://")
            cookie.maxAgeInSeconds = 8 * 60 * 60
            transform(SessionTransportTransformerMessageAuthentication(SESSION_SIGNING_KEY))
        }
    }

    /*
     * Makes HeliumID the identity service for this application's own bearer API.
     *
     * `audience` is the important line. Without it any token this issuer minted for any of its
     * clients would be accepted here, which is token substitution waiting to happen: another
     * application's token, obtained for another purpose, would authenticate against this API.
     * The value must match the `audiences` the client was registered with.
     *
     * Verification is offline against the cached JWKS. Add
     *     introspection { enabled = true; clientId = …; clientSecret = … }
     * if you need a revoked token to stop working before it expires, at the cost of a round trip.
     */
    install(HeliumId) {
        issuer = config.issuer
        audience = config.audience
        jwks { cacheFor = 10.minutes }
    }

    install(StatusPages) {
        exception<Throwable> { call, cause ->
            // Never the exception message: it can carry a URL, a header or a token fragment.
            log.error("unhandled failure on {}", call.request.local.uri, cause)
            call.respond(
                HttpStatusCode.InternalServerError,
                ApiError("internal_error", "Something went wrong. The details are in the server log."),
            )
        }
    }

    routing {
        oauthLoginRoutes(config, client, sessions, idTokens)
        webRoutes(config, client, sessions, workspace, clock)
        documentsApi(workspace, clock)
    }
}

/**
 * Signing key for the session cookie.
 *
 * Fixed so sessions survive a restart while you are trying the demo. A real deployment reads this
 * from its secret manager — a key in source control means anyone can mint a session cookie.
 */
private val SESSION_SIGNING_KEY: ByteArray =
    "demo-only-session-signing-key-not-a-secret".toByteArray()
