package dev.kamiql.helium.client

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Every failure [HeliumIdClient] can report, as a closed set of types.
 *
 * Callers branch on the *type*, not on a string. That is the whole reason this hierarchy
 * exists: a `when` over a sealed interface stops compiling when a case is missed, whereas
 * `if (error.code == "mfa_required")` fails silently the day the catalogue grows.
 *
 * The server's stable machine-readable `code` (RFC 9457 extension member, concept §5.4) is
 * always preserved verbatim in [code] even when it maps onto a broad variant, so nothing is
 * lost: [Unexpected] still tells you exactly which code arrived.
 *
 * Usage:
 * ```kotlin
 * val tokens = try {
 *     client.login("ada@example.com", password)
 * } catch (e: HeliumApiException) {
 *     when (val error = e.error) {
 *         is HeliumError.MfaRequired -> openChallengeUi(error.transactionId, error.methods)
 *         is HeliumError.InvalidCredentials -> showGenericFailure()   // never "no such user"
 *         is HeliumError.RateLimited -> backOff(error.retryAfter)
 *         else -> throw e
 *     }
 * }
 * ```
 */
public sealed interface HeliumError {

    /** The server's stable error code, e.g. `mfa_required`. Never changes without a version bump. */
    public val code: String

    /** The HTTP status that carried this error. */
    public val status: Int

    /**
     * A fixed, non-sensitive sentence from the server.
     *
     * It is safe to log and identical for every occurrence of the same [code]; it never embeds
     * a username, email, token or provider payload. It is *not* localised and generally not
     * suitable to show to an end user verbatim.
     */
    public val detail: String

    /** Correlation id, when the server sent one. Quote it in bug reports. */
    public val requestId: String?

    /**
     * No credentials, or credentials that are no longer usable.
     *
     * Covers `auth_required`, `invalid_token`, `token_expired` and `token_revoked` — read
     * [code] to tell them apart. The correct reaction is almost always the same: refresh the
     * access token, and if that fails, send the user back through authentication.
     */
    public data class AuthenticationRequired(
        override val code: String,
        override val detail: String,
        override val requestId: String? = null,
        override val status: Int = 401,
    ) : HeliumError

    /**
     * The credentials presented are not valid.
     *
     * Deliberately identical whether the account is missing, the password is wrong, or the
     * account uses a different credential type. Do not try to distinguish the cases in your UI:
     * the server refuses to tell you, precisely so your UI cannot become an account-enumeration
     * oracle.
     */
    public data class InvalidCredentials(
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "invalid_credentials"
        override val status: Int get() = 401
    }

    /**
     * The first factor succeeded; a second one is required to finish.
     *
     * Carries everything needed to open the right challenge UI without another round trip.
     * Complete it with [HeliumIdClient.verifyMfa] before [expiresAt]; the transaction is
     * one-time and expiry means starting over, not retrying.
     *
     * @property transactionId one-time handle for this challenge. Not a credential, but do not
     *           log it either — it is the other half of a login in progress.
     * @property methods the methods this user may use, e.g. `totp`, `recovery_code`.
     */
    public data class MfaRequired(
        public val transactionId: String,
        public val methods: List<String>,
        public val expiresAt: Instant?,
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "mfa_required"
        override val status: Int get() = 401
    }

    /**
     * The session is authentic but too old for this operation.
     *
     * Sensitive changes (password, email, MFA, client secrets) demand a fresh proof of
     * identity. Re-prompt for the password, then retry the original request.
     */
    public data class ReauthenticationRequired(
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "reauthentication_required"
        override val status: Int get() = 401
    }

    /** The account exists and the password was right, but the email address is unverified. */
    public data class EmailUnverified(
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "email_unverified"
        override val status: Int get() = 403
    }

    /**
     * The account is suspended, locked, disabled, or must set a new password before continuing.
     *
     * Read [code] (`account_suspended`, `account_locked`, `account_disabled`,
     * `password_reset_required`) when the distinction matters to your UI.
     */
    public data class AccountUnavailable(
        override val code: String,
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val status: Int get() = 403
    }

    /**
     * Authenticated, but not permitted.
     *
     * @property requiredPermission the permission or scope the server named, when it named one.
     *           Absent by design for checks where naming it would leak policy.
     */
    public data class Forbidden(
        override val detail: String,
        public val requiredPermission: String? = null,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "forbidden"
        override val status: Int get() = 403
    }

    /** The resource does not exist — or the caller may not know that it does. */
    public data class NotFound(
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "not_found"
        override val status: Int get() = 404
    }

    /**
     * A state conflict the caller can resolve.
     *
     * Covers `conflict`, `provider_already_linked`, `identity_already_linked`,
     * `last_credential_removal`, `provider_link_required` and `idempotency_conflict`; see
     * [code]. Notably, `identity_already_linked` means the external identity belongs to a
     * *different* account — the server will never silently merge the two.
     */
    public data class Conflict(
        override val code: String,
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val status: Int get() = 409
    }

    /**
     * The payload failed validation.
     *
     * @property fields field name to a non-sensitive reason, e.g. `password` -> `too_short`.
     *           The rejected value itself is never echoed back, so these are safe to log.
     */
    public data class ValidationFailed(
        public val fields: Map<String, String>,
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "validation_failed"
        override val status: Int get() = 422
    }

    /**
     * Too many requests.
     *
     * @property retryAfter how long to wait, taken from the `retry_after` member or the
     *           `Retry-After` header. Honour it; retrying sooner extends the penalty and is
     *           indistinguishable from an attack.
     */
    public data class RateLimited(
        public val retryAfter: Duration,
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val code: String get() = "rate_limited"
        override val status: Int get() = 429
    }

    /**
     * RFC 6749 `invalid_grant`: the code or refresh token is expired, revoked, or already used.
     *
     * On a refresh this is the signal that the token family is gone — either it simply expired,
     * or reuse was detected and every token in the family was revoked. Either way the only
     * correct response is a full re-authentication, **not** a retry with the same token.
     */
    public data class InvalidGrant(
        override val detail: String,
        override val requestId: String? = null,
        override val status: Int = 400,
    ) : HeliumError {
        override val code: String get() = "invalid_grant"
    }

    /** Transient. Retry with backoff; the request may well succeed unchanged. */
    public data class Unavailable(
        override val code: String,
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError {
        override val status: Int get() = 503
    }

    /**
     * Anything the SDK does not model as its own type.
     *
     * Both the status and the server's code are preserved, so protocol-level codes
     * (`pkce_verifier_invalid`, `redirect_uri_invalid`, `oauth_state_invalid`, …) and any code
     * added after this SDK was published still arrive intact rather than being swallowed.
     */
    public data class Unexpected(
        override val status: Int,
        override val code: String,
        override val detail: String,
        override val requestId: String? = null,
    ) : HeliumError
}

/**
 * Thrown by every [HeliumIdClient] call that does not succeed.
 *
 * The SDK throws rather than returning a `Result`: identity failures are exceptional in the
 * common path, and an exception cannot be ignored by accident the way an unchecked `Result`
 * can. Catch it once at your boundary and `when` over [error].
 *
 * The message is the error code only. [HeliumError.detail] is safe but uninteresting, and
 * nothing sensitive is ever put in a throwable that will end up in a stack trace.
 */
public class HeliumApiException(
    /** The typed failure. Branch on this. */
    public val error: HeliumError,
) : RuntimeException(error.code)

/**
 * Thrown when the identity server could not be reached or answered with something unparseable.
 *
 * Distinct from [HeliumApiException]: that one means "the server said no", this one means
 * "there was no usable answer". Treat it as transient.
 */
public class HeliumTransportException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

// --- wire shapes and mapping ---------------------------------------------------------

/**
 * RFC 9457 Problem Details as HeliumID sends it.
 *
 * Public because a caller may want to inspect the raw document; prefer [HeliumError].
 */
@Serializable
public data class ProblemDetails(
    public val type: String = "about:blank",
    public val title: String = "",
    public val status: Int = 0,
    public val code: String = "",
    public val detail: String = "",
    @SerialName("request_id") public val requestId: String? = null,
    @SerialName("transaction_id") public val transactionId: String? = null,
    @SerialName("retry_after") public val retryAfter: Long? = null,
    public val methods: List<String>? = null,
    @SerialName("expires_at") public val expiresAt: String? = null,
    public val errors: Map<String, String>? = null,
)

/**
 * RFC 6749 §5.2 error, which is what `/oauth2/token` and `/oauth2/revoke` return.
 *
 * The protocol endpoints deliberately do **not** speak problem+json: conforming OAuth clients
 * parse `error` and nothing else, and returning problem+json there would break them.
 */
@Serializable
public data class OAuthErrorResponse(
    public val error: String,
    @SerialName("error_description") public val errorDescription: String? = null,
)

/**
 * Maps a problem document onto the typed hierarchy.
 *
 * @param httpStatus the transport status, used when the document omits or disagrees on `status`
 *        (a proxy rewriting the body is rarer than one rewriting the status, but neither is
 *        trusted blindly).
 * @param retryAfterHeader value of the `Retry-After` header, used when the body omits it.
 */
internal fun ProblemDetails.toHeliumError(httpStatus: Int, retryAfterHeader: Long?): HeliumError {
    val effectiveStatus = if (status != 0) status else httpStatus
    return when (code) {
        "auth_required", "invalid_token", "token_expired", "token_revoked" ->
            HeliumError.AuthenticationRequired(code, detail, requestId, effectiveStatus)

        "invalid_credentials" -> HeliumError.InvalidCredentials(detail, requestId)

        "mfa_required" -> HeliumError.MfaRequired(
            // A challenge without a handle is unusable; surface it as unexpected rather than
            // pretending an empty transaction id is workable.
            transactionId = transactionId ?: return HeliumError.Unexpected(
                effectiveStatus,
                code,
                detail,
                requestId,
            ),
            methods = methods.orEmpty(),
            expiresAt = expiresAt?.let { runCatching { Instant.parse(it) }.getOrNull() },
            detail = detail,
            requestId = requestId,
        )

        "reauthentication_required" -> HeliumError.ReauthenticationRequired(detail, requestId)
        "email_unverified" -> HeliumError.EmailUnverified(detail, requestId)

        "account_suspended", "account_locked", "account_disabled", "password_reset_required" ->
            HeliumError.AccountUnavailable(code, detail, requestId)

        "forbidden", "unauthorized_client", "consent_required" ->
            HeliumError.Forbidden(detail, requiredPermission = null, requestId = requestId)

        "not_found" -> HeliumError.NotFound(detail, requestId)

        "conflict", "provider_already_linked", "identity_already_linked",
        "last_credential_removal", "provider_link_required", "idempotency_conflict",
        -> HeliumError.Conflict(code, detail, requestId)

        "validation_failed" -> HeliumError.ValidationFailed(errors.orEmpty(), detail, requestId)

        "rate_limited" -> HeliumError.RateLimited(
            retryAfter = (retryAfter ?: retryAfterHeader ?: 0L).seconds,
            detail = detail,
            requestId = requestId,
        )

        "invalid_grant", "pkce_verifier_invalid" ->
            HeliumError.InvalidGrant(detail, requestId, effectiveStatus)

        "temporarily_unavailable", "provider_unavailable" ->
            HeliumError.Unavailable(code, detail, requestId)

        else -> HeliumError.Unexpected(effectiveStatus, code, detail, requestId)
    }
}

/**
 * Maps an RFC 6749 error onto the typed hierarchy.
 *
 * Only the codes that carry an actionable distinction get their own variant; the rest stay as
 * [HeliumError.Unexpected] with the OAuth code intact, because inventing a type per protocol
 * error would suggest a branching decision the caller does not actually have.
 */
internal fun OAuthErrorResponse.toHeliumError(httpStatus: Int, retryAfterHeader: Long?): HeliumError {
    val message = errorDescription.orEmpty()
    return when (error) {
        "invalid_grant" -> HeliumError.InvalidGrant(message, requestId = null, status = httpStatus)
        "invalid_client" -> HeliumError.Forbidden(message, requiredPermission = null, requestId = null)
        "slow_down" -> HeliumError.RateLimited((retryAfterHeader ?: 0L).seconds, message)
        "temporarily_unavailable" -> HeliumError.Unavailable(error, message)
        else -> HeliumError.Unexpected(httpStatus, error, message)
    }
}
