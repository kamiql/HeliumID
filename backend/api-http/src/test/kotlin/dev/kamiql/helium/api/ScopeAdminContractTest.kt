package dev.kamiql.helium.api

import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.error.AuthError
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The wire contract of `/v1/admin/scopes`.
 *
 * Field names here are public API — a scope editor is written against them — and the status
 * codes are what tells a caller apart "you may not" from "you may, but not this scope". Both are
 * asserted rather than left to review.
 *
 * Route wiring itself is not exercised: `api-http` has no `testApplication` harness yet, because
 * `HeliumApiDependencies` needs twenty-odd repositories and no shared fixture builds one. That
 * gap predates this change and is tracked separately; the flow behaviour these routes delegate to
 * is covered in `ScopeAdminFlowsTest`.
 */
class ScopeAdminContractTest {

    /** The same configuration `installHeliumPlugins` gives ContentNegotiation. */
    private val json = Json {
        explicitNulls = false
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    // --- response shape ------------------------------------------------------------------

    @Test
    fun `a scope serializes with snake_case built_in`() {
        val encoded = json.encodeToString(
            ScopeResponse.serializer(),
            Scope("workspace:read", "See your documents", implicit = false, builtIn = false).toResponse(),
        ).let(json::parseToJsonElement).jsonObject

        assertEquals(setOf("name", "description", "implicit", "built_in"), encoded.keys)
        assertEquals("workspace:read", encoded.getValue("name").jsonPrimitive.content)
        assertEquals("See your documents", encoded.getValue("description").jsonPrimitive.content)
        assertFalse(encoded.getValue("built_in").jsonPrimitive.content.toBoolean())
    }

    @Test
    fun `the standard scopes report themselves as built in`() {
        val responses = Scope.STANDARD.map { it.toResponse() }

        assertTrue(responses.all { it.builtIn }, "a client must be able to render these read-only")
        assertTrue(responses.single { it.name == Scope.OPENID }.implicit)
    }

    // --- request shape -------------------------------------------------------------------

    @Test
    fun `implicit defaults to false when the body omits it`() {
        val request = json.decodeFromString(
            UpsertScopeRequest.serializer(),
            """{"description":"See your documents"}""",
        )

        // A scope the user never sees on the consent screen is a scope they never declined, so
        // the safe default is the visible one.
        assertFalse(request.implicit)
        assertEquals("See your documents", request.description)
    }

    @Test
    fun `the name is not part of the body`() {
        // It travels in the path. Accepting it here too would allow a body that disagrees with
        // the URL, and then the route has to decide which one wins.
        val encoded = json.encodeToString(
            UpsertScopeRequest.serializer(),
            UpsertScopeRequest(description = "See your documents"),
        ).let(json::parseToJsonElement).jsonObject

        assertEquals(setOf("description", "implicit"), encoded.keys)
    }

    // --- status codes --------------------------------------------------------------------

    @Test
    fun `the refusals map to the documented statuses`() {
        // Built-in scope, and scope still used by a client.
        assertEquals(HttpStatusCode.Conflict, ProblemMapper.statusFor(AuthError.Conflict))
        // Malformed name or description.
        assertEquals(
            HttpStatusCode.UnprocessableEntity,
            ProblemMapper.statusFor(AuthError.ValidationFailed(mapOf("name" to "invalid"))),
        )
        // Missing `admin:client:write`.
        assertEquals(HttpStatusCode.Forbidden, ProblemMapper.statusFor(AuthError.Forbidden("admin:client:write")))
        // A bearer token, or a session that authenticated too long ago.
        assertEquals(HttpStatusCode.Unauthorized, ProblemMapper.statusFor(AuthError.ReauthenticationRequired))
        assertEquals(HttpStatusCode.NotFound, ProblemMapper.statusFor(AuthError.NotFound))
    }

    @Test
    fun `a conflict does not say which rule was broken`() {
        // "built in" and "still in use" answer identically on purpose: both are `conflict`, and
        // the detail text must not turn the endpoint into a probe for which clients hold a scope.
        val problem = ProblemMapper.toProblem(AuthError.Conflict, requestId = "req_test")

        assertEquals("conflict", problem.code)
        assertFalse(problem.detail.contains("client", ignoreCase = true))
    }
}
