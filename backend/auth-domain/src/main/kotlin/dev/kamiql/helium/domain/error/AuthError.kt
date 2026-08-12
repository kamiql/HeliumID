package dev.kamiql.helium.domain.error

import dev.kamiql.helium.domain.common.TransactionId
import java.time.Duration
import java.time.Instant

/**
 * Every failure the domain can express, with the stable machine-readable `code` from concept
 * §5.4.
 *
 * The domain deliberately does **not** know about HTTP. `api-http` owns the status mapping
 * (concept §5.5) via a single exhaustive `when`, which is why this is a sealed hierarchy:
 * adding an error forces the mapping to be updated.
 *
 * `detail` is a fixed, non-sensitive sentence. It must never embed a username, email, token
 * or provider payload — concept §5.3: "Do not use `detail` to reveal sensitive information."
 */
sealed interface AuthError {

    /** Stable identifier clients branch on. Never change one without a version bump. */
    val code: String

    /** Coarse grouping used for metrics and for the HTTP status mapping. */
    val category: AuthErrorCategory

    /** Safe, generic explanation. Same text for every occurrence of the same code. */
    val detail: String

    // --- authentication -----------------------------------------------------

    data object AuthenticationRequired : AuthError {
        override val code = "auth_required"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "Authentication is required."
    }

    /**
     * Deliberately identical whether the account is missing, the password is wrong, or the
     * credential type does not exist. Concept §2.6 / CLAUDE.md: never reveal existence.
     */
    data object InvalidCredentials : AuthError {
        override val code = "invalid_credentials"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "The credentials provided are not valid."
    }

    data object InvalidToken : AuthError {
        override val code = "invalid_token"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "The token is not valid."
    }

    data object TokenExpired : AuthError {
        override val code = "token_expired"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "The token has expired."
    }

    data object TokenRevoked : AuthError {
        override val code = "token_revoked"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "The token has been revoked."
    }

    data object ReauthenticationRequired : AuthError {
        override val code = "reauthentication_required"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "Confirm your identity again to continue."
    }

    /**
     * Carries the transaction handle and the methods the user may use, so the client can open
     * the right challenge UI without a second round trip (concept §5.3 example payload).
     */
    data class MfaRequired(
        val transactionId: TransactionId,
        val methods: Set<String>,
        val expiresAt: Instant,
    ) : AuthError {
        override val code = "mfa_required"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "Complete the additional authentication step."
    }

    data object MfaInvalid : AuthError {
        override val code = "mfa_invalid"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "The additional authentication response is not valid."
    }

    data object MfaExpired : AuthError {
        override val code = "mfa_expired"
        override val category = AuthErrorCategory.AUTHENTICATION
        override val detail = "The additional authentication step expired. Start again."
    }

    // --- account state ------------------------------------------------------

    data object EmailUnverified : AuthError {
        override val code = "email_unverified"
        override val category = AuthErrorCategory.ACCOUNT_STATE
        override val detail = "Verify your email address to continue."
    }

    data object AccountSuspended : AuthError {
        override val code = "account_suspended"
        override val category = AuthErrorCategory.ACCOUNT_STATE
        override val detail = "This account is suspended."
    }

    data object AccountLocked : AuthError {
        override val code = "account_locked"
        override val category = AuthErrorCategory.ACCOUNT_STATE
        override val detail = "This account is temporarily locked."
    }

    data object AccountDisabled : AuthError {
        override val code = "account_disabled"
        override val category = AuthErrorCategory.ACCOUNT_STATE
        override val detail = "This account is disabled."
    }

    data object PasswordResetRequired : AuthError {
        override val code = "password_reset_required"
        override val category = AuthErrorCategory.ACCOUNT_STATE
        override val detail = "Set a new password to continue."
    }

    // --- oauth / provider ---------------------------------------------------

    data object ProviderUnavailable : AuthError {
        override val code = "provider_unavailable"
        override val category = AuthErrorCategory.TEMPORARY
        override val detail = "The identity provider is currently unavailable."
    }

    data object ProviderDenied : AuthError {
        override val code = "provider_denied"
        override val category = AuthErrorCategory.PROVIDER
        override val detail = "The identity provider denied the request."
    }

    data object ProviderInvalidResponse : AuthError {
        override val code = "provider_invalid_response"
        override val category = AuthErrorCategory.PROVIDER
        override val detail = "The identity provider returned an unusable response."
    }

    /**
     * The external identity is unknown and automatic linking is forbidden. The client must
     * start an authenticated linking flow — concept §9.4.
     */
    data object ProviderLinkRequired : AuthError {
        override val code = "provider_link_required"
        override val category = AuthErrorCategory.PROVIDER
        override val detail = "Sign in and link this provider to your account first."
    }

    data object ProviderAlreadyLinked : AuthError {
        override val code = "provider_already_linked"
        override val category = AuthErrorCategory.CONFLICT
        override val detail = "This provider is already linked to your account."
    }

    /** The `(issuer, subject)` pair belongs to a different account. Never auto-merge. */
    data object IdentityAlreadyLinked : AuthError {
        override val code = "identity_already_linked"
        override val category = AuthErrorCategory.CONFLICT
        override val detail = "This identity is already linked to another account."
    }

    /**
     * Unlinking would leave the account with no way in. Concept §2.6 "Unlink OAuth provider".
     */
    data object LastCredentialRemoval : AuthError {
        override val code = "last_credential_removal"
        override val category = AuthErrorCategory.CONFLICT
        override val detail = "Keep at least one way to sign in to your account."
    }

    data object OAuthStateInvalid : AuthError {
        override val code = "oauth_state_invalid"
        override val category = AuthErrorCategory.PROTOCOL
        override val detail = "The authorization state is missing, expired or already used."
    }

    data object OAuthNonceInvalid : AuthError {
        override val code = "oauth_nonce_invalid"
        override val category = AuthErrorCategory.PROTOCOL
        override val detail = "The identity token nonce did not match."
    }

    data object PkceVerifierInvalid : AuthError {
        override val code = "pkce_verifier_invalid"
        override val category = AuthErrorCategory.PROTOCOL
        override val detail = "The PKCE code verifier did not match the challenge."
    }

    /**
     * Never redirects and never echoes the offending URI: doing either turns the authorization
     * server into an open redirector.
     */
    data object RedirectUriInvalid : AuthError {
        override val code = "redirect_uri_invalid"
        override val category = AuthErrorCategory.PROTOCOL
        override val detail = "The redirect URI is not registered for this client."
    }

    data object UnauthorizedClient : AuthError {
        override val code = "unauthorized_client"
        override val category = AuthErrorCategory.AUTHORIZATION
        override val detail = "This client is not allowed to perform this request."
    }

    data object InvalidGrant : AuthError {
        override val code = "invalid_grant"
        override val category = AuthErrorCategory.PROTOCOL
        override val detail = "The grant is expired, revoked or was already used."
    }

    data class InvalidScope(val rejected: Set<String>) : AuthError {
        override val code = "invalid_scope"
        override val category = AuthErrorCategory.PROTOCOL
        override val detail = "One or more requested scopes are not permitted for this client."
    }

    data object ConsentRequired : AuthError {
        override val code = "consent_required"
        override val category = AuthErrorCategory.AUTHORIZATION
        override val detail = "The user must approve the requested scopes."
    }

    // --- validation and infrastructure --------------------------------------

    /**
     * @param fields field name to a **non-sensitive** reason, e.g. `password` -> `too_short`.
     *        Never include the rejected value itself.
     */
    data class ValidationFailed(val fields: Map<String, String>) : AuthError {
        override val code = "validation_failed"
        override val category = AuthErrorCategory.VALIDATION
        override val detail = "The request payload failed validation."
    }

    data object Conflict : AuthError {
        override val code = "conflict"
        override val category = AuthErrorCategory.CONFLICT
        override val detail = "The resource is in a conflicting state."
    }

    data object NotFound : AuthError {
        override val code = "not_found"
        override val category = AuthErrorCategory.NOT_FOUND
        override val detail = "The resource does not exist."
    }

    data class Forbidden(val requiredPermission: String? = null) : AuthError {
        override val code = "forbidden"
        override val category = AuthErrorCategory.AUTHORIZATION
        override val detail = "You do not have permission to perform this action."
    }

    data class RateLimited(val retryAfter: Duration) : AuthError {
        override val code = "rate_limited"
        override val category = AuthErrorCategory.RATE_LIMIT
        override val detail = "Too many requests. Try again later."
    }

    data object TemporarilyUnavailable : AuthError {
        override val code = "temporarily_unavailable"
        override val category = AuthErrorCategory.TEMPORARY
        override val detail = "The service is temporarily unavailable."
    }

    /** Same idempotency key replayed with a different request body. */
    data object IdempotencyConflict : AuthError {
        override val code = "idempotency_conflict"
        override val category = AuthErrorCategory.CONFLICT
        override val detail = "This idempotency key was already used with a different payload."
    }
}

/** Coarse grouping used for the HTTP status mapping and for low-cardinality metric labels. */
enum class AuthErrorCategory {
    AUTHENTICATION,
    AUTHORIZATION,
    ACCOUNT_STATE,
    VALIDATION,
    CONFLICT,
    NOT_FOUND,
    RATE_LIMIT,
    PROVIDER,
    PROTOCOL,
    TEMPORARY,
}

/**
 * Thrown only at the boundary between the flow engine and a transaction, so that a failing
 * requirement rolls the transaction back. Flows themselves return
 * [dev.kamiql.helium.domain.error.AuthError] values rather than throwing.
 */
class AuthErrorException(val error: AuthError) : RuntimeException(error.code) {
    /** Suppresses the stack trace: these are control flow, not defects, and they are frequent. */
    override fun fillInStackTrace(): Throwable = this
}
