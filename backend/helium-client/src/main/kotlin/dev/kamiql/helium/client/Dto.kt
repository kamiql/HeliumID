package dev.kamiql.helium.client

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The HeliumID wire contract, mirrored for SDK consumers.
 *
 * These types are copies of `api-http`'s `Dto.kt` rather than a shared module on purpose. The
 * SDK must be publishable and consumable on its own, without dragging `auth-domain`,
 * `flow-engine` and the persistence layer onto a subsidiary service's classpath. The price is
 * that the two files have to stay in step; the `@SerialName` values below are the contract and
 * changing one is a breaking change on both sides.
 *
 * Every field is exactly what the server sends. Nothing here is a convenience projection —
 * if a value is absent from the server response it is nullable or defaulted here too, so a
 * missing field never turns into a silent zero.
 */

// --- authentication ------------------------------------------------------------

/** Body of `POST /v1/auth/register`. */
@Serializable
public data class RegisterRequest(
    public val username: String,
    public val email: String,
    public val password: String,
    public val firstName: String = "",
    public val lastName: String = "",
)

/** Body of `POST /v1/auth/login`. */
@Serializable
public data class LoginRequest(
    /** Username or email; the server normalises both. */
    public val identifier: String,
    public val password: String,
)

/** Body of `POST /v1/auth/mfa/verify`, completing a challenge from [HeliumError.MfaRequired]. */
@Serializable
public data class MfaVerifyRequest(
    @SerialName("transaction_id") public val transactionId: String,
    /** `totp`, `recovery_code` or `webauthn`. */
    public val method: String,
    public val code: String,
)

/** A single opaque one-time token: email verification, email-change confirmation, reset. */
@Serializable
public data class TokenRequestBody(public val token: String)

/** An email address on its own, for the endpoints that must not reveal whether it exists. */
@Serializable
public data class EmailRequest(public val email: String)

/** Body of `POST /v1/auth/password-reset/complete`. */
@Serializable
public data class PasswordResetCompleteRequest(
    public val token: String,
    @SerialName("new_password") public val newPassword: String,
)

/** Body of `PUT /v1/me/password`. */
@Serializable
public data class ChangePasswordRequest(
    @SerialName("current_password") public val currentPassword: String,
    @SerialName("new_password") public val newPassword: String,
)

/** Body of `POST /v1/me/email-change`. */
@Serializable
public data class EmailChangeRequest(
    @SerialName("new_email") public val newEmail: String,
    @SerialName("current_password") public val currentPassword: String,
)

/** Body of `PUT /v1/me`. `null` means "leave unchanged". */
@Serializable
public data class UpdateProfileRequest(
    public val username: String? = null,
    public val firstName: String? = null,
    public val lastName: String? = null,
)

/** Body of `POST /v1/me/delete`. */
@Serializable
public data class DeleteAccountRequest(
    @SerialName("current_password") public val currentPassword: String? = null,
)

/**
 * Returned for every accepted-but-unfinished operation.
 *
 * Registration, verification resend and password reset all answer with this and nothing else,
 * so the response is byte-identical whether or not the address exists. Do not try to infer
 * account existence from it — there is nothing to infer.
 */
@Serializable
public data class AcceptedResponse(public val status: String = "accepted")

// --- account -------------------------------------------------------------------

/** The authenticated user as `/v1/me` reports them. */
@Serializable
public data class UserResponse(
    public val id: String,
    public val username: String,
    public val email: String,
    @SerialName("email_verified") public val emailVerified: Boolean,
    public val firstName: String,
    public val lastName: String,
    /** `ACTIVE`, `SUSPENDED`, `LOCKED`, `DISABLED`, … */
    public val status: String,
    public val roles: List<String>,
    public val permissions: List<String>,
    @SerialName("mfa_enabled") public val mfaEnabled: Boolean,
    /** ISO-8601 instant in UTC. */
    @SerialName("created_at") public val createdAt: String,
)

/** One active browser session. */
@Serializable
public data class SessionResponse(
    public val id: String,
    public val device: String?,
    @SerialName("created_at") public val createdAt: String,
    @SerialName("last_seen_at") public val lastSeenAt: String,
    @SerialName("expires_at") public val expiresAt: String,
    /** True for the session that made the request, so a UI can label it "this device". */
    public val current: Boolean,
)

/** An external identity provider linked to the account. */
@Serializable
public data class LinkedProviderResponse(
    public val provider: String,
    public val email: String?,
    @SerialName("linked_at") public val linkedAt: String,
    @SerialName("last_login_at") public val lastLoginAt: String?,
)

/** One MFA factor. */
@Serializable
public data class MfaFactorResponse(
    public val id: String,
    /** `totp`, `recovery_code`, `webauthn`. */
    public val type: String,
    public val label: String,
    public val status: String,
    @SerialName("created_at") public val createdAt: String,
    @SerialName("last_used_at") public val lastUsedAt: String?,
)

/**
 * The only response that ever carries a TOTP secret.
 *
 * It is shown once and is not re-fetchable. Render it, let the user scan it, and drop the
 * reference — never persist or log [secret] or [otpauthUri].
 */
@Serializable
public data class TotpEnrollmentResponse(
    @SerialName("factor_id") public val factorId: String,
    public val secret: String,
    @SerialName("otpauth_uri") public val otpauthUri: String,
)

/**
 * Recovery codes, returned once at enrollment or regeneration.
 *
 * Same rule as [TotpEnrollmentResponse]: display, then discard. The server stores only hashes
 * and cannot reissue these.
 */
@Serializable
public data class RecoveryCodesResponse(public val codes: List<String>)

/** Body of `POST /v1/me/mfa/totp/confirm`. */
@Serializable
public data class TotpConfirmRequest(
    @SerialName("factor_id") public val factorId: String,
    public val code: String,
)

/** Body of `POST /v1/me/mfa/totp/disable`. */
@Serializable
public data class TotpDisableRequest(
    @SerialName("factor_id") public val factorId: String,
    @SerialName("current_password") public val currentPassword: String? = null,
)

/** Password policy, so a UI can show a live checklist instead of guessing. */
@Serializable
public data class PasswordRequirementsResponse(
    @SerialName("min_length") public val minLength: Int,
    @SerialName("max_length") public val maxLength: Int,
    @SerialName("breached_check") public val breachedCheck: Boolean,
    @SerialName("rejects_identifier") public val rejectsIdentifier: Boolean,
)

/** Whoami payload the SPA uses to bootstrap and to obtain a CSRF token. */
@Serializable
public data class SessionBootstrapResponse(
    public val authenticated: Boolean,
    public val user: UserResponse? = null,
    @SerialName("csrf_token") public val csrfToken: String,
)

/** Providers the login UI may offer. */
@Serializable
public data class ProviderListResponse(public val providers: List<String>)

// --- administration ----------------------------------------------------------------

/** A page of results. `total` is the unfiltered match count, not the page size. */
@Serializable
public data class PageResponse<T>(
    public val items: List<T>,
    public val total: Long,
    public val limit: Int,
    public val offset: Long,
)

/** A user as the admin surface sees them. Carries no permissions and no MFA detail. */
@Serializable
public data class AdminUserResponse(
    public val id: String,
    public val username: String,
    public val email: String,
    @SerialName("email_verified") public val emailVerified: Boolean,
    public val firstName: String,
    public val lastName: String,
    public val status: String,
    public val roles: List<String>,
    @SerialName("created_at") public val createdAt: String,
    @SerialName("updated_at") public val updatedAt: String,
)

/** Body of `PUT /v1/admin/users/{id}/status`. */
@Serializable
public data class UpdateUserStatusRequest(public val status: String)

/** Body of `PUT /v1/admin/users/{id}/roles`. Replaces the whole set. */
@Serializable
public data class AssignRolesRequest(public val roles: List<String>)

/** Result of `POST /v1/admin/users/{id}/revoke-sessions`. */
@Serializable
public data class RevokedSessionsResponse(public val revoked: Int)

/** A role and the permissions it grants. */
@Serializable
public data class RoleResponse(
    public val name: String,
    public val description: String,
    public val color: String,
    public val permissions: List<String>,
    /** Built-in roles cannot be edited or deleted: code depends on them. */
    @SerialName("built_in") public val builtIn: Boolean,
)

/** Body of `PUT /v1/admin/roles/{name}`. */
@Serializable
public data class UpsertRoleRequest(
    public val name: String,
    public val description: String = "",
    public val color: String = "#5865F2",
    public val permissions: List<String> = emptyList(),
)

/**
 * A registered OAuth client.
 *
 * `has_secret` rather than the secret or its hash: the plaintext is unrecoverable by design,
 * and the hash has no business leaving the database.
 */
@Serializable
public data class ClientResponse(
    @SerialName("client_id") public val clientId: String,
    public val name: String,
    /** `PUBLIC` or `CONFIDENTIAL`. */
    public val type: String,
    @SerialName("has_secret") public val hasSecret: Boolean,
    @SerialName("secret_rotated_at") public val secretRotatedAt: String?,
    @SerialName("redirect_uris") public val redirectUris: List<String>,
    public val scopes: List<String>,
    @SerialName("grant_types") public val grantTypes: List<String>,
    public val audiences: List<String>,
    @SerialName("skip_consent") public val skipConsent: Boolean,
    public val enabled: Boolean,
    @SerialName("created_at") public val createdAt: String,
)

/** Body of `POST /v1/admin/clients`. */
@Serializable
public data class RegisterClientRequest(
    @SerialName("client_id") public val clientId: String,
    public val name: String,
    /** `PUBLIC` or `CONFIDENTIAL`. SPAs and native apps are `PUBLIC` and use PKCE. */
    public val type: String = "PUBLIC",
    @SerialName("redirect_uris") public val redirectUris: List<String>,
    public val scopes: List<String> = listOf("openid", "profile", "email"),
    @SerialName("grant_types") public val grantTypes: List<String> = listOf("authorization_code", "refresh_token"),
    public val audiences: List<String> = emptyList(),
    @SerialName("skip_consent") public val skipConsent: Boolean = false,
)

/** Body of `PATCH /v1/admin/clients/{id}`. `null` means "leave unchanged". */
@Serializable
public data class UpdateClientRequest(
    public val name: String? = null,
    @SerialName("redirect_uris") public val redirectUris: List<String>? = null,
    public val scopes: List<String>? = null,
    @SerialName("grant_types") public val grantTypes: List<String>? = null,
    public val audiences: List<String>? = null,
    @SerialName("skip_consent") public val skipConsent: Boolean? = null,
    public val enabled: Boolean? = null,
)

/**
 * The one and only time a client secret is returned.
 *
 * Store it in your secret manager immediately. Registration and rotation are the only two
 * responses that contain it, and neither can be replayed.
 */
@Serializable
public data class ClientSecretResponse(
    @SerialName("client_id") public val clientId: String,
    /** `null` for public clients, which have no secret by definition. */
    public val secret: String?,
    @SerialName("rotated_at") public val rotatedAt: String,
)

/** One audit record. `metadata` never contains credentials, tokens or raw provider payloads. */
@Serializable
public data class AuditRecordResponse(
    public val id: String,
    @SerialName("event_type") public val eventType: String,
    public val outcome: String,
    @SerialName("actor_user_id") public val actorUserId: String?,
    @SerialName("subject_user_id") public val subjectUserId: String?,
    @SerialName("client_id") public val clientId: String?,
    @SerialName("request_id") public val requestId: String,
    public val metadata: Map<String, String>,
    @SerialName("created_at") public val createdAt: String,
)

/** A scope the authorization server knows about. */
@Serializable
public data class ScopeResponse(
    public val name: String,
    public val description: String,
    /** Implicit scopes are granted without an explicit consent tick. */
    public val implicit: Boolean,
)

// --- OAuth protocol ------------------------------------------------------------------

/** RFC 6749 §5.1 token response. */
@Serializable
public data class TokenEndpointResponse(
    @SerialName("access_token") public val accessToken: String,
    @SerialName("token_type") public val tokenType: String = "Bearer",
    /** Seconds until [accessToken] expires. Refresh before this elapses, not after a 401. */
    @SerialName("expires_in") public val expiresIn: Long,
    /**
     * Present when `offline_access` / `refresh_token` was granted.
     *
     * Refresh tokens rotate: the value returned by a refresh replaces the one you sent, and
     * re-using a spent token revokes the entire family. Persist the new value atomically.
     */
    @SerialName("refresh_token") public val refreshToken: String? = null,
    @SerialName("id_token") public val idToken: String? = null,
    /** Space-delimited list of the scopes actually granted, which may be fewer than requested. */
    public val scope: String,
) {
    /** [scope] split into a set, for callers that would otherwise re-parse it everywhere. */
    public val grantedScopes: Set<String>
        get() = scope.split(' ').filter { it.isNotBlank() }.toSet()
}

/** OIDC discovery document. */
@Serializable
public data class DiscoveryResponse(
    public val issuer: String,
    @SerialName("authorization_endpoint") public val authorizationEndpoint: String,
    @SerialName("token_endpoint") public val tokenEndpoint: String,
    @SerialName("userinfo_endpoint") public val userinfoEndpoint: String,
    @SerialName("jwks_uri") public val jwksUri: String,
    @SerialName("revocation_endpoint") public val revocationEndpoint: String,
    @SerialName("introspection_endpoint") public val introspectionEndpoint: String,
    @SerialName("end_session_endpoint") public val endSessionEndpoint: String,
    @SerialName("scopes_supported") public val scopesSupported: List<String>,
    @SerialName("response_types_supported") public val responseTypesSupported: List<String>,
    @SerialName("grant_types_supported") public val grantTypesSupported: List<String>,
    @SerialName("subject_types_supported") public val subjectTypesSupported: List<String>,
    @SerialName("id_token_signing_alg_values_supported")
    public val idTokenSigningAlgValuesSupported: List<String>,
    @SerialName("token_endpoint_auth_methods_supported")
    public val tokenEndpointAuthMethodsSupported: List<String>,
    @SerialName("code_challenge_methods_supported") public val codeChallengeMethodsSupported: List<String>,
    @SerialName("claims_supported") public val claimsSupported: List<String>,
)

/**
 * RFC 7662 introspection response.
 *
 * `active = false` is the only reliable signal; every other field is absent for an inactive
 * token and must not be treated as evidence of anything.
 */
@Serializable
public data class IntrospectionResponse(
    public val active: Boolean,
    public val scope: String? = null,
    @SerialName("client_id") public val clientId: String? = null,
    public val username: String? = null,
    @SerialName("token_type") public val tokenType: String? = null,
    public val exp: Long? = null,
    public val iat: Long? = null,
    public val sub: String? = null,
    public val aud: List<String>? = null,
    public val iss: String? = null,
    public val jti: String? = null,
)

/** OIDC Core §5.3 `userinfo` claims, gated on the granted scopes. */
@Serializable
public data class UserInfoResponse(
    public val sub: String,
    public val name: String? = null,
    @SerialName("preferred_username") public val preferredUsername: String? = null,
    @SerialName("given_name") public val givenName: String? = null,
    @SerialName("family_name") public val familyName: String? = null,
    public val email: String? = null,
    @SerialName("email_verified") public val emailVerified: Boolean? = null,
    @SerialName("updated_at") public val updatedAt: Long? = null,
)

/** Consent screen payload, returned by `/oauth2/authorize` when approval is still needed. */
@Serializable
public data class ConsentPromptResponse(
    @SerialName("client_id") public val clientId: String,
    @SerialName("client_name") public val clientName: String,
    public val scopes: List<ScopeDescription>,
    @SerialName("return_to") public val returnTo: String,
)

/** One scope on the consent screen. */
@Serializable
public data class ScopeDescription(public val name: String, public val description: String)
