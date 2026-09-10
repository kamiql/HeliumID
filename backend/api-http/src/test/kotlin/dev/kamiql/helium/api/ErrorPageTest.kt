package dev.kamiql.helium.api

import dev.kamiql.helium.domain.error.AuthError
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.withCharset
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Which serialization of an error a caller gets, and what the HTML one is allowed to contain.
 *
 * The split matters in both directions. A browser navigating to `/api/oauth2/authorize` or a
 * provider callback used to be shown a raw JSON document; a conforming OAuth client shown a page
 * instead of `{"error":...}` would break just as badly. Both halves are asserted here because
 * the negotiation is invisible — nothing fails loudly if it silently starts answering one caller
 * in the other's format.
 */
class ErrorPageTest {

    /** Mirrors `installHeliumPlugins`, so negotiation behaves as it does in the real server. */
    private fun testServer(error: AuthError, block: suspend (io.ktor.client.HttpClient) -> Unit) =
        testApplication {
            application {
                install(ContentNegotiation) {
                    json(Json { explicitNulls = false; encodeDefaults = true })
                }
                routing {
                    get("/boom") { call.respondProblem(error) }
                }
            }
            block(client)
        }

    @Test
    fun `a browser navigation renders a page, not a json document`() = testServer(AuthError.RedirectUriInvalid) { client ->
        val response = client.get("/boom") {
            // What Chrome, Firefox and Safari all send on a top-level navigation.
            header(HttpHeaders.Accept, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        }
        val body = response.bodyAsText()

        assertEquals(HttpStatusCode.BadRequest, response.status, "status must not change with the format")
        assertEquals(ContentType.Text.Html.withCharset(Charsets.UTF_8), response.contentType())
        assertTrue(body.startsWith("<!DOCTYPE html>"), "expected a document, got: ${body.take(80)}")
        assertFalse(body.trimStart().startsWith("{"), "a browser must never be shown the raw problem")
    }

    @Test
    fun `an api client still gets problem json`() = testServer(AuthError.RedirectUriInvalid) { client ->
        val response = client.get("/boom") { header(HttpHeaders.Accept, "application/json") }
        val body = response.bodyAsText()

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertTrue(body.trimStart().startsWith("{"), "expected json, got: ${body.take(80)}")
        assertTrue(body.contains("\"code\":\"redirect_uri_invalid\""), "the stable code must survive")
    }

    /**
     * The case that protects every machine endpoint. An OAuth client library sending a wildcard
     * Accept — or nothing at all — must not be handed markup.
     */
    @Test
    fun `a wildcard accept is not treated as a request for html`() = testServer(AuthError.InvalidGrant) { client ->
        val wildcard = client.get("/boom") { header(HttpHeaders.Accept, "*/*") }.bodyAsText()
        val absent = client.get("/boom").bodyAsText()

        assertTrue(wildcard.trimStart().startsWith("{"), "*/* must resolve to json")
        assertTrue(absent.trimStart().startsWith("{"), "no Accept header must resolve to json")
    }

    /** `Accept: application/json, text/html;q=0.1` is asking for JSON, and q-values say so. */
    @Test
    fun `html is only chosen when it outranks json`() = testServer(AuthError.InvalidGrant) { client ->
        val jsonPreferred = client.get("/boom") {
            header(HttpHeaders.Accept, "application/json, text/html;q=0.1")
        }.bodyAsText()

        assertTrue(jsonPreferred.trimStart().startsWith("{"), "a lower-ranked text/html must not win")
    }

    /**
     * Concept §5.3: `detail` must not reveal anything sensitive, and the page is a second place
     * that rule has to hold. It renders a fixed sentence per code plus the correlation id — never
     * an exception, a stack frame or a class name.
     */
    @Test
    fun `the page carries no internal detail and no script`() = testServer(AuthError.TemporarilyUnavailable) { client ->
        val body = client.get("/boom") { header(HttpHeaders.Accept, "text/html") }.bodyAsText()

        assertFalse(body.contains("<script", ignoreCase = true), "prod CSP forbids inline script")
        assertFalse(body.contains("Exception", ignoreCase = true))
        assertFalse(body.contains("dev.kamiql"), "no class or package names")
        assertFalse(body.contains("http://", ignoreCase = true), "no external references")
        assertTrue(body.contains("temporarily_unavailable"), "the code is what support will ask for")
    }

    /** Status and headers are a property of the error, not of the format the caller asked for. */
    @Test
    fun `headers are identical in both formats`() = testServer(AuthError.AuthenticationRequired) { client ->
        val html = client.get("/boom") { header(HttpHeaders.Accept, "text/html") }
        val json = client.get("/boom") { header(HttpHeaders.Accept, "application/json") }

        assertEquals(HttpStatusCode.Unauthorized, html.status)
        assertEquals(json.status, html.status)
        assertEquals(
            json.headers[HttpHeaders.WWWAuthenticate],
            html.headers[HttpHeaders.WWWAuthenticate],
            "the bearer challenge is required by concept §5.5 regardless of body format",
        )
    }
}
