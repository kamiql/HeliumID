package dev.kamiql.helium.api

import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.error.AuthError
import io.ktor.http.HttpStatusCode
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The error contract is public API: clients branch on `code`, and the concept's §5.5 table
 * pins the statuses. Changing either silently breaks every consumer, so both are asserted.
 */
class ProblemMapperTest {

    @Test
    fun `status mapping matches concept section 5-5`() {
        val expected = mapOf<AuthError, HttpStatusCode>(
            AuthError.AuthenticationRequired to HttpStatusCode.Unauthorized,
            AuthError.InvalidCredentials to HttpStatusCode.Unauthorized,
            AuthError.InvalidToken to HttpStatusCode.Unauthorized,
            AuthError.MfaInvalid to HttpStatusCode.Unauthorized,
            AuthError.EmailUnverified to HttpStatusCode.Forbidden,
            AuthError.AccountSuspended to HttpStatusCode.Forbidden,
            AuthError.Forbidden() to HttpStatusCode.Forbidden,
            AuthError.ValidationFailed(emptyMap()) to HttpStatusCode.UnprocessableEntity,
            AuthError.Conflict to HttpStatusCode.Conflict,
            AuthError.RateLimited(Duration.ofSeconds(30)) to HttpStatusCode.TooManyRequests,
            AuthError.ProviderUnavailable to HttpStatusCode.ServiceUnavailable,
            AuthError.NotFound to HttpStatusCode.NotFound,
            AuthError.RedirectUriInvalid to HttpStatusCode.BadRequest,
        )

        expected.forEach { (error, status) ->
            assertEquals(status, ProblemMapper.statusFor(error), "wrong status for ${error.code}")
        }
    }

    @Test
    fun `mfa required carries everything the client needs to open the challenge`() {
        val expiresAt = Instant.parse("2026-08-12T14:30:00Z")
        val error = AuthError.MfaRequired(
            transactionId = TransactionId("mfa_tx_01J"),
            methods = setOf("totp", "recovery_code"),
            expiresAt = expiresAt,
        )

        val problem = ProblemMapper.toProblem(error, "req_01J")

        // This shape is the concept §5.3 example payload.
        assertEquals("mfa_required", problem.code)
        assertEquals(401, problem.status)
        assertEquals("mfa_tx_01J", problem.transactionId)
        assertEquals(listOf("recovery_code", "totp"), problem.methods)
        assertEquals(expiresAt.toString(), problem.expiresAt)
        assertEquals("req_01J", problem.requestId)
    }

    @Test
    fun `rate limiting surfaces retry after`() {
        val problem = ProblemMapper.toProblem(AuthError.RateLimited(Duration.ofSeconds(90)), null)

        assertEquals(90, problem.retryAfter)
        assertEquals(429, problem.status)
    }

    @Test
    fun `validation failures carry field reasons but never values`() {
        val problem = ProblemMapper.toProblem(
            AuthError.ValidationFailed(mapOf("password" to "too_short", "email" to "invalid")),
            null,
        )

        assertEquals("too_short", assertNotNull(problem.errors)["password"])
        // The reason is a stable token, not prose and not the rejected input.
        assertFalse(problem.errors.orEmpty().values.any { it.contains(" ") })
    }

    @Test
    fun `no error detail leaks whether an account exists`() {
        val invalid = ProblemMapper.toProblem(AuthError.InvalidCredentials, null)

        assertFalse(invalid.detail.contains("password", ignoreCase = true))
        assertFalse(invalid.detail.contains("user", ignoreCase = true))
        assertFalse(invalid.detail.contains("exist", ignoreCase = true))
    }

    @Test
    fun `the type uri is derived from the stable code`() {
        val problem = ProblemMapper.toProblem(AuthError.ReauthenticationRequired, null)

        assertTrue(problem.type.endsWith("/reauthentication-required"))
        assertEquals("reauthentication_required", problem.code)
    }

    @Test
    fun `oauth errors use the RFC 6749 shape rather than problem json`() {
        assertEquals("invalid_client", AuthError.UnauthorizedClient.toOAuthError().error)
        assertEquals("invalid_grant", AuthError.InvalidGrant.toOAuthError().error)
        // PKCE failure is an invalid grant on the wire; `pkce_verifier_invalid` is the
        // richer internal code and is not what a conforming OAuth client parses.
        assertEquals("invalid_grant", AuthError.PkceVerifierInvalid.toOAuthError().error)
        assertEquals("invalid_scope", AuthError.InvalidScope(setOf("admin")).toOAuthError().error)

        assertEquals(HttpStatusCode.Unauthorized, AuthError.UnauthorizedClient.toOAuthStatus())
        assertEquals(HttpStatusCode.BadRequest, AuthError.InvalidGrant.toOAuthStatus())
    }

    @Test
    fun `an invalid scope error does not echo the rejected scopes into the description`() {
        val response = AuthError.InvalidScope(setOf("internal:secret")).toOAuthError()

        assertNull(response.errorDescription?.takeIf { it.contains("internal:secret") })
    }
}
