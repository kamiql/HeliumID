package dev.kamiql.helium.demo

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import dev.kamiql.helium.client.HeliumIdClient
import dev.kamiql.helium.demo.auth.IdTokenVerifier
import dev.kamiql.helium.demo.auth.LOGIN_HANDLE_COOKIE
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respondError
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The callback endpoint, which is where a relying party is attacked.
 *
 * Every case below ends the attempt rather than repairing it. That is deliberate: a callback that
 * cannot be tied to an authorization request this application started is not a login, and the
 * only safe response is to discard it.
 *
 * No token exchange happens in any of these — each is refused before the code is spent — so the
 * mock engine is only there to satisfy the SDK's constructor.
 */
class CallbackRoutesTest {

    private val config = DemoConfig(
        issuer = "https://id.example",
        baseUrl = "http://localhost:8081",
        port = 8081,
        clientId = "helium-demo",
        clientSecret = "test-secret",
        audience = "helium-demo-api",
        scopes = setOf("openid", "profile"),
    )

    /** Fails every call: reaching HeliumID at all would mean a check did not fire first. */
    private fun refusingClient() = HeliumIdClient(
        config.issuer,
        io.ktor.client.HttpClient(MockEngine { respondError(HttpStatusCode.ServiceUnavailable) }),
    )

    private fun ApplicationTestBuilder.demo() = application {
        demoModule(
            config = config,
            client = refusingClient(),
            idTokens = IdTokenVerifier(
                issuer = config.issuer,
                clientId = config.clientId,
                keys = ImmutableJWKSet(JWKSet()),
            ),
        )
    }

    /** Follows nothing: the assertions are about the redirect itself. */
    private fun ApplicationTestBuilder.nonFollowingClient() = createClient { followRedirects = false }

    @Test
    fun `login redirects to the authorization endpoint with PKCE and a nonce`() = testApplication {
        demo()

        val response = nonFollowingClient().get("/login")

        assertEquals(HttpStatusCode.Found, response.status)
        val location = Url(assertNotNull(response.headers[HttpHeaders.Location]))
        assertEquals("/oauth2/authorize", location.encodedPath)

        val query = location.parameters
        assertEquals("code", query["response_type"])
        assertEquals(config.clientId, query["client_id"])
        assertEquals(config.redirectUri, query["redirect_uri"])
        // S256 only. A `plain` challenge offers nothing against an attacker who can see the
        // authorization request, and HeliumID rejects it outright.
        assertEquals("S256", query["code_challenge_method"])
        assertTrue(!query["code_challenge"].isNullOrBlank())
        assertTrue(!query["state"].isNullOrBlank())
        assertTrue(!query["nonce"].isNullOrBlank())

        // The verifier itself must never appear in the URL.
        assertTrue(query["code_verifier"] == null)

        val cookie = assertNotNull(response.headers[HttpHeaders.SetCookie])
        assertTrue(cookie.contains(LOGIN_HANDLE_COOKIE))
        assertTrue(cookie.contains("HttpOnly"), "the login handle must be out of reach of scripts")
    }

    @Test
    fun `a callback with no pending login is refused`() = testApplication {
        demo()

        val response = nonFollowingClient().get("/callback?code=abc&state=whatever")

        response.assertRedirectedTo("/?error=no_pending_login")
    }

    /**
     * The CSRF defence for the code flow.
     *
     * PKCE does not cover this: it proves the code was requested by this client, not that it was
     * requested for this browser. An attacker who can get their own authorization code delivered
     * to a victim's browser logs the victim into the attacker's account without it.
     */
    @Test
    fun `a callback whose state does not match is refused`() = testApplication {
        demo()
        val client = nonFollowingClient()

        val handle = client.get("/login").loginHandle()
        val response = client.get("/callback?code=abc&state=forged") {
            headers.append(HttpHeaders.Cookie, "$LOGIN_HANDLE_COOKIE=$handle")
        }

        response.assertRedirectedTo("/?error=state_mismatch")
    }

    @Test
    fun `a callback with no state at all is refused`() = testApplication {
        demo()
        val client = nonFollowingClient()

        val handle = client.get("/login").loginHandle()
        val response = client.get("/callback?code=abc") {
            headers.append(HttpHeaders.Cookie, "$LOGIN_HANDLE_COOKIE=$handle")
        }

        response.assertRedirectedTo("/?error=state_mismatch")
    }

    /**
     * Replay protection. A captured callback URL opened a second time must find nothing, even
     * though its `state` was once correct.
     */
    @Test
    fun `a login handle cannot be used twice`() = testApplication {
        demo()
        val client = nonFollowingClient()

        val start = client.get("/login")
        val handle = start.loginHandle()
        val state = Url(assertNotNull(start.headers[HttpHeaders.Location])).parameters["state"]

        // First use: correct state, so it gets as far as the token exchange, which the refusing
        // engine fails. That is fine — the transaction is consumed either way.
        client.get("/callback?code=abc&state=$state") {
            headers.append(HttpHeaders.Cookie, "$LOGIN_HANDLE_COOKIE=$handle")
        }

        val replay = client.get("/callback?code=abc&state=$state") {
            headers.append(HttpHeaders.Cookie, "$LOGIN_HANDLE_COOKIE=$handle")
        }

        replay.assertRedirectedTo("/?error=no_pending_login")
    }

    @Test
    fun `a provider error is reported without touching the token endpoint`() = testApplication {
        demo()
        val client = nonFollowingClient()

        val handle = client.get("/login").loginHandle()
        val response = client.get("/callback?error=access_denied") {
            headers.append(HttpHeaders.Cookie, "$LOGIN_HANDLE_COOKIE=$handle")
        }

        response.assertRedirectedTo("/?error=authorization_refused")
    }

    @Test
    fun `login only accepts a local return_to`() = testApplication {
        demo()
        val client = nonFollowingClient()

        // An absolute URL here would make /login an open redirect back onto the attacker's site
        // once the round trip completes.
        val response = client.get("/login?return_to=https://evil.example/steal")

        assertEquals(HttpStatusCode.Found, response.status)
        // It still starts a login; the hostile target is simply dropped in favour of "/".
        assertTrue(assertNotNull(response.headers[HttpHeaders.Location]).startsWith(config.issuer))
    }

    @Test
    fun `the bearer API refuses an unauthenticated caller`() = testApplication {
        demo()

        val response = nonFollowingClient().get("/api/documents")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(
            assertNotNull(response.headers[HttpHeaders.WWWAuthenticate]).contains("Bearer"),
            "a bearer API must say so in its challenge",
        )
    }

    // --- helpers ------------------------------------------------------------------------

    private fun HttpResponse.loginHandle(): String {
        val cookie = assertNotNull(headers[HttpHeaders.SetCookie])
        return cookie.substringAfter("$LOGIN_HANDLE_COOKIE=").substringBefore(";")
    }

    private fun HttpResponse.assertRedirectedTo(location: String) {
        assertEquals(HttpStatusCode.Found, status)
        assertEquals(location, headers[HttpHeaders.Location])
    }
}
