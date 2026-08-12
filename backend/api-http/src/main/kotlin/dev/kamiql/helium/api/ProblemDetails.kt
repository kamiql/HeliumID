package dev.kamiql.helium.api

import dev.kamiql.helium.domain.error.AuthError
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.callid.callId
import io.ktor.server.response.header
import io.ktor.server.response.respond
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * RFC 9457 Problem Details.
 *
 * The `code` field is the contract clients branch on (concept §5.3/§5.4). `title` and `detail`
 * are for humans and may be reworded; `code`, `status` and the extension fields may not be
 * changed without a version bump.
 */
@Serializable
data class ProblemDetails(
    val type: String,
    val title: String,
    val status: Int,
    val code: String,
    val detail: String,
    @SerialName("request_id") val requestId: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("retry_after") val retryAfter: Long? = null,
    val methods: List<String>? = null,
    @SerialName("expires_at") val expiresAt: String? = null,
    /** Field-level validation reasons. Never contains the rejected value itself. */
    val errors: Map<String, String>? = null,
)

/**
 * The single place [AuthError] becomes an HTTP response.
 *
 * The `when` is exhaustive over a sealed hierarchy, so adding an error to the domain will not
 * compile until its status is decided here. That is the point: no error can slip out with a
 * default status nobody thought about.
 *
 * Statuses follow concept §5.5.
 */
object ProblemMapper {

    /** Base URI for the human-readable error documentation. */
    var typeBaseUri: String = "https://helium.id/errors"

    fun statusFor(error: AuthError): HttpStatusCode = when (error) {
        // 401 — the caller may retry with (different or additional) credentials.
        AuthError.AuthenticationRequired,
        AuthError.InvalidCredentials,
        AuthError.InvalidToken,
        AuthError.TokenExpired,
        AuthError.TokenRevoked,
        AuthError.ReauthenticationRequired,
        is AuthError.MfaRequired,
        AuthError.MfaInvalid,
        AuthError.MfaExpired,
        -> HttpStatusCode.Unauthorized

        // 403 — authenticated, but not permitted in this state.
        AuthError.EmailUnverified,
        AuthError.AccountSuspended,
        AuthError.AccountLocked,
        AuthError.AccountDisabled,
        AuthError.PasswordResetRequired,
        AuthError.ConsentRequired,
        is AuthError.Forbidden,
        AuthError.UnauthorizedClient,
        -> HttpStatusCode.Forbidden

        // 409 — a state conflict the caller can resolve.
        AuthError.Conflict,
        AuthError.ProviderAlreadyLinked,
        AuthError.IdentityAlreadyLinked,
        AuthError.LastCredentialRemoval,
        AuthError.IdempotencyConflict,
        -> HttpStatusCode.Conflict

        // Concept §5.5 leaves this as "409 or 403, depending on flow". 409 is the better fit:
        // the account exists and the caller must take an action to reconcile it.
        AuthError.ProviderLinkRequired -> HttpStatusCode.Conflict

        AuthError.NotFound -> HttpStatusCode.NotFound

        is AuthError.ValidationFailed -> HttpStatusCode.UnprocessableEntity

        is AuthError.RateLimited -> HttpStatusCode.TooManyRequests

        // 400 — protocol-level errors, per RFC 6749 §5.2.
        AuthError.OAuthStateInvalid,
        AuthError.OAuthNonceInvalid,
        AuthError.PkceVerifierInvalid,
        AuthError.RedirectUriInvalid,
        AuthError.InvalidGrant,
        is AuthError.InvalidScope,
        AuthError.ProviderDenied,
        AuthError.ProviderInvalidResponse,
        -> HttpStatusCode.BadRequest

        // 503 — transient; the caller should retry later.
        AuthError.ProviderUnavailable,
        AuthError.TemporarilyUnavailable,
        -> HttpStatusCode.ServiceUnavailable
    }

    fun toProblem(error: AuthError, requestId: String?): ProblemDetails {
        val status = statusFor(error)
        return ProblemDetails(
            type = "$typeBaseUri/${error.code.replace('_', '-')}",
            title = titleFor(error),
            status = status.value,
            code = error.code,
            detail = error.detail,
            requestId = requestId,
            transactionId = (error as? AuthError.MfaRequired)?.transactionId?.value,
            retryAfter = (error as? AuthError.RateLimited)?.retryAfter?.seconds,
            methods = (error as? AuthError.MfaRequired)?.methods?.sorted(),
            expiresAt = (error as? AuthError.MfaRequired)?.expiresAt?.toString(),
            errors = (error as? AuthError.ValidationFailed)?.fields,
        )
    }

    private fun titleFor(error: AuthError): String = when (error) {
        is AuthError.MfaRequired -> "Additional authentication required"
        AuthError.AuthenticationRequired -> "Authentication required"
        AuthError.InvalidCredentials -> "Invalid credentials"
        AuthError.ReauthenticationRequired -> "Confirm your identity"
        AuthError.EmailUnverified -> "Email address not verified"
        is AuthError.RateLimited -> "Too many requests"
        is AuthError.ValidationFailed -> "Validation failed"
        is AuthError.Forbidden -> "Not permitted"
        AuthError.NotFound -> "Not found"
        else -> error.code.replace('_', ' ').replaceFirstChar { it.uppercase() }
    }
}

/**
 * Writes a problem response, including the headers a client needs to react correctly.
 *
 * `Retry-After` and `WWW-Authenticate` are part of the contract, not decoration: concept §5.5
 * requires the bearer challenge header, and a `429` without `Retry-After` forces clients to
 * invent their own backoff.
 */
suspend fun ApplicationCall.respondProblem(error: AuthError, requestId: String? = null) {
    val problem = ProblemMapper.toProblem(error, requestId ?: correlationId)
    val status = HttpStatusCode.fromValue(problem.status)

    problem.retryAfter?.let { response.header(HttpHeaders.RetryAfter, it.toString()) }

    if (status == HttpStatusCode.Unauthorized) {
        val bearerError = when (error) {
            AuthError.TokenExpired -> "invalid_token"
            AuthError.InvalidToken, AuthError.TokenRevoked -> "invalid_token"
            else -> "invalid_request"
        }
        response.header(
            HttpHeaders.WWWAuthenticate,
            """Bearer realm="identity", error="$bearerError"""",
        )
    }

    respond(status, problem)
}

/** The correlation id assigned by the `CallId` plugin. */
val ApplicationCall.correlationId: String?
    get() = callId

/**
 * OAuth error responses use RFC 6749 §5.2's shape, not problem+json.
 *
 * Clients and libraries parse `error` / `error_description` at the token endpoint; returning
 * problem+json there would break every conforming OAuth client.
 */
@Serializable
data class OAuthErrorResponse(
    val error: String,
    @SerialName("error_description") val errorDescription: String? = null,
)

/** Maps a domain error onto the closest RFC 6749 §5.2 error code. */
fun AuthError.toOAuthError(): OAuthErrorResponse = when (this) {
    AuthError.UnauthorizedClient -> OAuthErrorResponse("invalid_client", detail)
    AuthError.InvalidGrant -> OAuthErrorResponse("invalid_grant", detail)
    AuthError.PkceVerifierInvalid -> OAuthErrorResponse("invalid_grant", detail)
    is AuthError.InvalidScope -> OAuthErrorResponse("invalid_scope", detail)
    AuthError.RedirectUriInvalid -> OAuthErrorResponse("invalid_request", detail)
    is AuthError.ValidationFailed -> OAuthErrorResponse("invalid_request", detail)
    is AuthError.RateLimited -> OAuthErrorResponse("slow_down", detail)
    AuthError.TemporarilyUnavailable, AuthError.ProviderUnavailable ->
        OAuthErrorResponse("temporarily_unavailable", detail)
    else -> OAuthErrorResponse("invalid_request", detail)
}

/** OAuth error responses carry the status the RFC prescribes, which is not the §5.5 mapping. */
fun AuthError.toOAuthStatus(): HttpStatusCode = when (this) {
    AuthError.UnauthorizedClient -> HttpStatusCode.Unauthorized
    is AuthError.RateLimited -> HttpStatusCode.TooManyRequests
    AuthError.TemporarilyUnavailable, AuthError.ProviderUnavailable -> HttpStatusCode.ServiceUnavailable
    else -> HttpStatusCode.BadRequest
}

internal fun Map<String, String>.toJsonObject(): JsonObject =
    JsonObject(mapValues<String, String, JsonElement> { JsonPrimitive(it.value) })
