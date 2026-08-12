package dev.kamiql.helium.client

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.auth.authenticate
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Negative-path tests for the server plugin.
 *
 * These deliberately cover the cases where a mistake fails *open*: a missing token, a malformed
 * token, and an authorization gate with no principal behind it. The happy path needs a live
 * JWKS endpoint and belongs in the integration suite.
 */
class HeliumIdPluginTest {

    private fun protectedApp(block: suspend (io.ktor.client.HttpClient) -> Unit) = testApplication {
        application {
            install(HeliumId) {
                issuer = "https://id.example"
                audience = "orders-api"
            }
            routing {
                authenticate("heliumid") {
                    get("/open") { call.respondText("ok") }
                    requireScope("orders:read") {
                        get("/scoped") { call.respondText("ok") }
                    }
                    requireRole("ADMINISTRATOR") {
                        get("/roled") { call.respondText("ok") }
                    }
                }
            }
        }
        block(client)
    }

    @Test
    fun `missing token is rejected with a bearer challenge and problem json`() = protectedApp { client ->
        val response = client.get("/open")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(
            """Bearer realm="identity", error="invalid_request"""",
            response.headers[HttpHeaders.WWWAuthenticate],
        )
        assertTrue(response.headers[HttpHeaders.ContentType]!!.startsWith("application/problem+json"))
        assertTrue(response.bodyAsText().contains("\"code\":\"auth_required\""))
    }

    @Test
    fun `garbage token is rejected as invalid_token without explaining why`() = protectedApp { client ->
        val response = client.get("/open") {
            header(HttpHeaders.Authorization, "Bearer not-a-jwt")
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(
            """Bearer realm="identity", error="invalid_token"""",
            response.headers[HttpHeaders.WWWAuthenticate],
        )
        val body = response.bodyAsText()
        assertTrue(body.contains("\"code\":\"invalid_token\""))
        // The response must not hint at the parse failure; that is free debugging for a forger.
        assertTrue(!body.contains("signature") && !body.contains("parse"))
    }

    @Test
    fun `a non-bearer scheme is not accepted`() = protectedApp { client ->
        val response = client.get("/open") {
            header(HttpHeaders.Authorization, "Basic dXNlcjpwYXNz")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `scope gate denies rather than falling through to the handler`() = protectedApp { client ->
        val response = client.get("/scoped")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(!response.bodyAsText().contains("ok"))
    }

    @Test
    fun `role gate denies rather than falling through to the handler`() = protectedApp { client ->
        val response = client.get("/roled")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(!response.bodyAsText().contains("ok"))
    }

    @Test
    fun `install fails fast when the issuer is missing`() {
        val failure = runCatching {
            HeliumIdConfig().apply { audience = "orders-api" }.validated()
        }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
    }

    @Test
    fun `introspection without client credentials is rejected at install time`() {
        val failure = runCatching {
            HeliumIdConfig().apply {
                issuer = "https://id.example"
                introspection { enabled = true }
            }.validated()
        }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
    }

    @Test
    fun `jwks uri defaults to the issuer's well-known location`() {
        val settings = HeliumIdConfig().apply { issuer = "https://id.example/" }.validated()
        assertEquals("https://id.example/.well-known/jwks.json", settings.jwksUri)
        assertEquals("https://id.example", settings.issuer)
    }
}
