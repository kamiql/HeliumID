package dev.kamiql.helium.app.support

import dev.kamiql.helium.app.HeliumComponents
import dev.kamiql.helium.app.HeliumConfig
import dev.kamiql.helium.app.HeliumEnvironment
import dev.kamiql.helium.app.HeliumRole
import dev.kamiql.helium.app.heliumModule
import dev.kamiql.helium.domain.credential.PasswordHashParameters
import dev.kamiql.helium.domain.mfa.MfaPolicy
import dev.kamiql.helium.domain.mfa.WebAuthnRelyingParty
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.redis.InMemoryRateLimiter
import dev.kamiql.helium.testing.PostgresFixture
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import java.util.Base64

/**
 * The whole application, in-process, against a real PostgreSQL.
 *
 * ### Why the real composition root
 *
 * This boots [HeliumComponents] — the production object graph — rather than assembling a test
 * one. Real repositories, real Argon2, real token issuer, real CSRF, real problem mapping,
 * migrations applied by Flyway exactly as in production. The alternative, a hand-wired graph of
 * fakes behind the HTTP layer, would test the routes against a system that does not exist: the
 * defects worth catching here live precisely in the wiring — a repository that was never passed
 * in, a cookie flag that only the composition root sets, a flow whose requirement is satisfied
 * by a fake but not by the real session service.
 *
 * Module-level unit tests keep using fakes, and should: they turn on state that is fiddly to
 * arrange through HTTP. This layer answers a different question — *does the assembled server
 * behave* — and only the assembled server can answer it.
 *
 * ### What is deliberately not real
 *
 * * **Redis.** Absent, so [HeliumComponents] falls back to its in-memory rate limiter and
 *   transaction store. That is a supported single-instance configuration, and the Redis
 *   implementations have their own container-backed suite in `persistence-redis`.
 * * **Argon2 cost.** Reduced to [CHEAP_ARGON2]. Production parameters target 100–300 ms per
 *   verification; a suite that logs in a few hundred times would spend minutes hashing. The
 *   algorithm and the encoding are unchanged, so the hasher is still under test — only the work
 *   factor moves, and `CryptoTest` covers the production parameters directly.
 * * **`secureCookies`.** Off, which drops the `__Host-` prefix, because the test transport is
 *   plain HTTP and a browser-shaped `Secure` cookie would never come back.
 *   [HttpSecurityCookieTest] asserts the prefix *is* applied when the flag is on.
 * * **SMTP.** No mail settings, so mail is logged rather than sent. Tests read tokens out of the
 *   outbox instead — see [OutboxReader].
 *
 * ### Lifecycle
 *
 * The container and the component graph are built once for the JVM and shared; each test
 * truncates. Building a graph per test would mean a fresh Hikari pool and a fresh Argon2
 * benchmark for every case. [reset] restores a clean database and re-warms the signing key,
 * which `truncateAll` removes along with everything else.
 */
object HeliumTestApp {

    /**
     * Argon2 at a work factor suited to a test suite, not to an attacker.
     *
     * Below the 19456 KiB floor `HeliumConfig.validate()` enforces in production — which is the
     * point: this configuration declares itself [HeliumEnvironment.DEV] and would be refused as
     * a production one.
     */
    val CHEAP_ARGON2 = PasswordHashParameters(
        memoryKib = 1024,
        iterations = 1,
        parallelism = 1,
        saltLength = 16,
        hashLength = 32,
        pepperVersion = 1,
    )

    const val ISSUER: String = "http://localhost"

    /** Fixed rather than random so a failing test reproduces byte for byte. */
    private val DATA_KEY = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })
    private val HMAC_KEY = Base64.getEncoder().encodeToString(ByteArray(32) { (it + 64).toByte() })

    val config: HeliumConfig by lazy {
        val container = PostgresFixture.container
        HeliumConfig(
            environment = HeliumEnvironment.DEV,
            role = HeliumRole.API,
            port = 0,
            bindHost = "127.0.0.1",
            issuerUrl = ISSUER,
            publicBaseUrl = ISSUER,
            allowedOrigins = setOf(ISSUER),
            // See the class KDoc: plain-HTTP transport, so no `Secure`, so no `__Host-` prefix.
            secureCookies = false,
            sameSite = "Lax",
            trustForwardedHeaders = false,
            database = HeliumConfig.DatabaseSettings(
                jdbcUrl = container.jdbcUrl,
                username = container.username,
                password = container.password,
                maxPoolSize = 8,
                // Idempotent, and this is the only place the schema is created for this graph.
                migrateOnStart = true,
            ),
            redisUrl = null,
            dataKeysBase64 = "1:$DATA_KEY",
            dataKeyVersion = 1,
            tokenHmacKeyBase64 = HMAC_KEY,
            passwordPepperBase64 = null,
            passwordPepperVersion = 1,
            argon2 = CHEAP_ARGON2,
            argon2Parallelism = 2,
            lifetimes = Lifetimes(),
            mfaPolicy = MfaPolicy.OPTIONAL,
            webAuthn = WebAuthnRelyingParty(
                id = "localhost",
                name = "HeliumID Test",
                origins = setOf(ISSUER),
            ),
            mail = null,
            google = null,
            github = null,
            discord = null,
            // The suite creates its own administrator through `Actors`, so the dev bootstrap
            // would only add a user every test then has to account for.
            bootstrapAdmin = null,
        )
    }

    val components: HeliumComponents by lazy { HeliumComponents(config) }

    /** Empties the database and restores the state the application needs to serve a request. */
    suspend fun reset() {
        PostgresFixture.truncateAll()

        // Rate-limit windows live in this process, not in the database, so truncation leaves
        // them untouched — and every request in the suite arrives from the same loopback
        // address, so the per-IP limits see one very busy client rather than N tests.
        // `RateLimit.REGISTRATION` allows five per hour; without this the sixth account the
        // suite creates would simply not be created, and registration answers `202` either way,
        // so the failure would surface much later as an inexplicable `401` at login.
        (components.rateLimiter as? InMemoryRateLimiter)?.clear()

        // `signing_keys` is truncated with everything else, and the token endpoint cannot issue
        // anything without an active key. Production generates the first one at startup; here
        // that has to happen again after every wipe.
        components.warmUp()
    }
}

/**
 * Runs [block] against a started HeliumID.
 *
 * Wraps `testApplication` so every suite gets the same client: a cookie jar, JSON content
 * negotiation, and redirects left unfollowed. **Unfollowed matters** — a good deal of this
 * server's behaviour *is* the redirect (an authorization response, a provider hand-off, a
 * callback landing), and a client that chases it silently turns the assertion into one about the
 * destination instead of about the `Location` header.
 */
fun heliumTest(block: suspend HeliumTestScope.() -> Unit) = testApplication {
    HeliumTestApp.components // force construction before the module asks for it
    HeliumTestApp.reset()

    application {
        heliumModule(HeliumTestApp.components, HeliumTestApp.config)
    }

    val http = createClient {
        install(HttpCookies)
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true; explicitNulls = false })
        }
        followRedirects = false
        expectSuccess = false
    }

    startApplication()
    HeliumTestScope(this, http).block()
}

/**
 * What a test sees: the HTTP client, the component graph, and the helpers built on them.
 *
 * The raw [ApplicationTestBuilder] is exposed for the rare case that needs a second, differently
 * configured client — a request with no cookie jar, say.
 */
class HeliumTestScope(
    val builder: ApplicationTestBuilder,
    rawClient: HttpClient,
) {
    val components: HeliumComponents get() = HeliumTestApp.components

    /** Route-recording, CSRF-attaching HTTP. Use this, not [rawHttp], so coverage is counted. */
    val http: HeliumTestClient = HeliumTestClient(rawClient)

    /** The unwrapped client, for assertions about transport behaviour itself. */
    val rawHttp: HttpClient = rawClient

    /** Reads what the flows published to the transactional outbox. */
    val outbox: OutboxReader = OutboxReader(HeliumTestApp.components)

    /** Creates and signs in users. */
    val actors: Actors = Actors(this)
}
