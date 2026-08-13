package dev.kamiql.helium.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The scope-catalogue half of the admin surface.
 *
 * Worth testing at this layer for two reasons: the scope name goes into the *path*, where a
 * colon must survive encoding intact, and both refusals the server can return are `conflict`,
 * which the SDK has to surface as a typed error rather than a bare non-2xx.
 */
class ScopeAdminClientTest {

    private lateinit var recorded: MutableList<HttpRequestData>

    private fun clientReturning(
        status: HttpStatusCode,
        body: String,
        contentType: String = ContentType.Application.Json.toString(),
    ): HeliumIdClient {
        recorded = mutableListOf()
        val engine = MockEngine { request ->
            recorded += request
            respond(
                content = ByteReadChannel(body),
                status = status,
                headers = headersOf(HttpHeaders.ContentType, contentType),
            )
        }
        return HeliumIdClient("https://id.example", HttpClient(engine))
    }

    @Test
    fun `upsert puts to the scope path and returns the stored scope`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.OK,
            """{"name":"workspace:read","description":"See your documents","implicit":false,"built_in":false}""",
        )

        val scope = client.upsertScope(
            "workspace:read",
            UpsertScopeRequest(description = "See your documents"),
        )

        assertEquals("workspace:read", scope.name)
        assertEquals("See your documents", scope.description)
        assertEquals(false, scope.builtIn)

        val request = recorded.single()
        assertEquals(HttpMethod.Put, request.method)
        // The colon is legal in a path segment and must not be percent-encoded into something
        // the server reads as a different scope name.
        assertEquals("/v1/admin/scopes/workspace:read", request.url.encodedPath)
    }

    @Test
    fun `built_in defaults to false when an older server omits it`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.OK,
            """[{"name":"profile","description":"See your name","implicit":false}]""",
        )

        assertEquals(false, client.listScopes().single().builtIn)
    }

    @Test
    fun `a built-in scope surfaces as a typed Conflict`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.Conflict,
            """{"type":"https://helium.id/errors/conflict","title":"Conflict","status":409,
                "code":"conflict","detail":"The request conflicts with the current state."}""",
            contentType = "application/problem+json",
        )

        val failure = assertFailsWith<HeliumApiException> {
            client.upsertScope("openid", UpsertScopeRequest("Hijacked"))
        }
        assertIs<HeliumError.Conflict>(failure.error)
    }

    @Test
    fun `delete sends DELETE and a scope still in use surfaces as Conflict`(): Unit = runBlocking {
        val ok = clientReturning(HttpStatusCode.NoContent, "")
        ok.deleteScope("workspace:read")
        assertEquals(HttpMethod.Delete, recorded.single().method)
        assertEquals("/v1/admin/scopes/workspace:read", recorded.single().url.encodedPath)

        val inUse = clientReturning(
            HttpStatusCode.Conflict,
            """{"type":"t","title":"Conflict","status":409,"code":"conflict","detail":"d"}""",
            contentType = "application/problem+json",
        )
        val failure = assertFailsWith<HeliumApiException> { inUse.deleteScope("workspace:read") }
        assertIs<HeliumError.Conflict>(failure.error)
    }

    @Test
    fun `the request body carries only description and implicit`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.OK,
            """{"name":"workspace:write","description":"Edit","implicit":true,"built_in":false}""",
        )

        client.upsertScope("workspace:write", UpsertScopeRequest("Edit", implicit = true))

        val body = recorded.single().body.toByteArrayText()
        assertTrue(body.contains("\"description\":\"Edit\""), body)
        assertTrue(body.contains("\"implicit\":true"), body)
        // The name lives in the path; sending it twice would let the two disagree.
        assertTrue(!body.contains("\"name\""), body)
    }
}

private fun io.ktor.http.content.OutgoingContent.toByteArrayText(): String =
    (this as io.ktor.http.content.TextContent).text
