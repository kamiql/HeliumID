package dev.kamiql.helium.app.support

import dev.kamiql.helium.api.LoginRequest
import dev.kamiql.helium.api.RegisterRequest
import dev.kamiql.helium.api.TokenRequestBody
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.policy.Role
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * Creates and signs in the people a test needs.
 *
 * ### Accounts are made the way a user makes one
 *
 * [create] drives `POST /v1/auth/register`, pulls the verification token out of the outbox and
 * redeems it through `POST /v1/auth/email/verify` — rather than inserting a row. Every test that
 * needs *a signed-in user* therefore also exercises registration end to end, and an account
 * arrives in exactly the state the real path leaves it in. Hand-built rows drift: they acquire
 * whatever fields the test author remembered, and a flow that starts depending on a new one
 * keeps passing against fixtures while failing in production.
 *
 * ### The one thing that is not done over HTTP
 *
 * Granting [Role.ADMINISTRATOR] is a direct repository write, because **there is no route that
 * does it for the first administrator** — that is `DevBootstrap`'s job, and it is deliberately
 * unreachable over the network. `PUT /v1/admin/users/{userId}/roles` needs an existing
 * administrator to call it, so bootstrapping one has to happen out of band exactly as it does in
 * production. Tests for the role-assignment route itself use an [admin] to grant to somebody
 * else, which keeps the route under test rather than replaced by this shortcut.
 */
class Actors(private val scope: HeliumTestScope) {

    /** Everything a test needs to act as, or reason about, one account. */
    data class Account(
        val userId: UserId,
        val username: String,
        val email: String,
        val password: String,
    )

    /**
     * Registers a verified account without signing it in.
     *
     * @param administrator grants `ADMINISTRATOR` alongside `USER`. See the class KDoc for why
     *        this one step bypasses HTTP.
     */
    suspend fun create(
        administrator: Boolean = false,
        password: String = PASSWORD,
        client: HeliumTestClient = scope.http,
    ): Account {
        val name = "actor${counter.incrementAndGet()}"
        val email = "$name@helium.test"

        client.bootstrapCsrf()

        val registered = client.post("/v1/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(username = name, email = email, password = password))
        }
        assertEquals(
            HttpStatusCode.Accepted, registered.status,
            "registration for '$name' was refused",
        )

        val token = scope.outbox.emailVerificationToken()
        val verified = client.post("/v1/auth/email/verify") {
            contentType(ContentType.Application.Json)
            setBody(TokenRequestBody(token))
        }
        assertEquals(
            HttpStatusCode.NoContent, verified.status,
            "email verification for '$name' was refused",
        )

        val user = scope.components.users.findByUsername(Username.parse(name)!!)
            ?: fail("registration reported success but no user '$name' exists")

        if (administrator) {
            scope.components.roles.assign(user.id, setOf(Role.ADMINISTRATOR, Role.USER))
        }

        return Account(userId = user.id, username = name, email = email, password = password)
    }

    /** Signs [account] in on [client], leaving its session cookie in that client's jar. */
    suspend fun signIn(account: Account, client: HeliumTestClient = scope.http) {
        client.bootstrapCsrf()
        val response = client.post("/v1/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(identifier = account.username, password = account.password))
        }
        assertEquals(
            HttpStatusCode.NoContent, response.status,
            "login for '${account.username}' was refused",
        )
    }

    /** A verified, signed-in ordinary user. */
    suspend fun user(client: HeliumTestClient = scope.http): Account =
        create(client = client).also { signIn(it, client) }

    /** A verified, signed-in administrator. */
    suspend fun admin(client: HeliumTestClient = scope.http): Account =
        create(administrator = true, client = client).also { signIn(it, client) }

    /**
     * A second client with its own cookie jar.
     *
     * Needed by every test that plays two people at once — the owner of a resource and somebody
     * reaching for it. Sharing one jar would mean signing out to switch identities, which loses
     * the first session and with it the ability to assert it still works.
     */
    fun separateClient(): HeliumTestClient = HeliumTestClient(
        scope.builder.createClient {
            install(HttpCookies)
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true; explicitNulls = false })
            }
            followRedirects = false
            expectSuccess = false
        },
    )

    private companion object {
        /** Long enough for the length policy, and obviously not a real one. */
        const val PASSWORD = "correct-horse-battery-staple-42"

        /**
         * Usernames are unique per JVM, not per test.
         *
         * Truncation between tests would make a per-test counter safe, but a shared one costs
         * nothing and removes a whole class of confusing failure — two accounts named `actor1`
         * in a suite that reads the outbox, where the wrong token is a plausible match.
         */
        val counter = AtomicInteger()
    }
}

/**
 * Fetches a CSRF token into the client's cookie jar.
 *
 * `GET /v1/auth/session` is the SPA's bootstrap and issues a fresh token on every call. Tests
 * call it through the client so the route is counted as exercised, which it genuinely is.
 */
suspend fun HeliumTestClient.bootstrapCsrf() {
    val response = get("/v1/auth/session")
    assertEquals(HttpStatusCode.OK, response.status, "session bootstrap failed")
}
