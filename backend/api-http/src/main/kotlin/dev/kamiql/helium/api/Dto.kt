package dev.kamiql.helium.api

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.identity.ExternalIdentity
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.user.User
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire types for the `/v1` API.
 *
 * These are separate from the domain model on purpose. A domain type serialized directly is a
 * standing invitation to leak a field that was added for internal use — `secretHash`,
 * `sessionHash`, `encryptedSecret`. Every field below was chosen deliberately.
 */

// --- authentication ------------------------------------------------------------

@Serializable
data class RegisterRequest(
    val username: String,
    val email: String,
    val password: String,
    val firstName: String = "",
    val lastName: String = "",
)

@Serializable
data class LoginRequest(
    /** Username or email. */
    val identifier: String,
    val password: String,
)

@Serializable
data class MfaVerifyRequest(
    @SerialName("transaction_id") val transactionId: String,
    /** `totp` or `recovery_code`. */
    val method: String,
    val code: String,
)

@Serializable
data class TokenRequestBody(val token: String)

@Serializable
data class EmailRequest(val email: String)

@Serializable
data class PasswordResetCompleteRequest(
    val token: String,
    @SerialName("new_password") val newPassword: String,
)

@Serializable
data class ChangePasswordRequest(
    @SerialName("current_password") val currentPassword: String,
    @SerialName("new_password") val newPassword: String,
)

@Serializable
data class EmailChangeRequest(
    @SerialName("new_email") val newEmail: String,
    @SerialName("current_password") val currentPassword: String,
)

@Serializable
data class UpdateProfileRequest(
    val username: String? = null,
    val firstName: String? = null,
    val lastName: String? = null,
)

@Serializable
data class DeleteAccountRequest(
    @SerialName("current_password") val currentPassword: String? = null,
)

/**
 * Sent for every accepted-but-unfinished operation.
 *
 * Registration and password reset both answer with this and nothing else, so the response is
 * identical whether or not the address exists (concept §2.6).
 */
@Serializable
data class AcceptedResponse(val status: String = "accepted")

// --- account -------------------------------------------------------------------

@Serializable
data class UserResponse(
    val id: String,
    val username: String,
    val email: String,
    @SerialName("email_verified") val emailVerified: Boolean,
    val firstName: String,
    val lastName: String,
    val status: String,
    val roles: List<String>,
    val permissions: List<String>,
    @SerialName("mfa_enabled") val mfaEnabled: Boolean,
    @SerialName("created_at") val createdAt: String,
)

fun User.toResponse(
    roles: Set<String>,
    permissions: Set<String>,
    mfaEnabled: Boolean,
): UserResponse = UserResponse(
    id = id.value.toString(),
    username = username.display,
    email = primaryEmail.display,
    emailVerified = isEmailVerified,
    firstName = firstName,
    lastName = lastName,
    status = status.name,
    roles = roles.sorted(),
    permissions = permissions.sorted(),
    mfaEnabled = mfaEnabled,
    createdAt = createdAt.toString(),
)

@Serializable
data class SessionResponse(
    val id: String,
    val device: String?,
    @SerialName("created_at") val createdAt: String,
    @SerialName("last_seen_at") val lastSeenAt: String,
    @SerialName("expires_at") val expiresAt: String,
    /** True for the session making this request, so the UI can label it. */
    val current: Boolean,
)

fun Session.toResponse(current: Boolean): SessionResponse = SessionResponse(
    id = id.value.toString(),
    device = deviceLabel,
    createdAt = createdAt.toString(),
    lastSeenAt = lastSeenAt.toString(),
    expiresAt = minOf(idleExpiresAt, absoluteExpiresAt).toString(),
    current = current,
)

@Serializable
data class LinkedProviderResponse(
    val provider: String,
    val email: String?,
    @SerialName("linked_at") val linkedAt: String,
    @SerialName("last_login_at") val lastLoginAt: String?,
)

fun ExternalIdentity.toResponse(): LinkedProviderResponse = LinkedProviderResponse(
    provider = providerKey.value,
    email = providerEmail?.display,
    linkedAt = createdAt.toString(),
    lastLoginAt = lastLoginAt?.toString(),
)

@Serializable
data class MfaFactorResponse(
    val id: String,
    val type: String,
    val label: String,
    val status: String,
    @SerialName("created_at") val createdAt: String,
    @SerialName("last_used_at") val lastUsedAt: String?,
)

fun MfaFactor.toResponse(): MfaFactorResponse = MfaFactorResponse(
    id = id.value.toString(),
    type = type.token,
    label = label,
    status = status.name,
    createdAt = createdAt.toString(),
    lastUsedAt = lastUsedAt?.toString(),
)

/** The only response that ever carries a TOTP secret. Shown once, never re-fetchable. */
@Serializable
data class TotpEnrollmentResponse(
    @SerialName("factor_id") val factorId: String,
    val secret: String,
    @SerialName("otpauth_uri") val otpauthUri: String,
)

/** Recovery codes, returned once at enrollment or regeneration. */
@Serializable
data class RecoveryCodesResponse(val codes: List<String>)

@Serializable
data class TotpConfirmRequest(
    @SerialName("factor_id") val factorId: String,
    val code: String,
)

@Serializable
data class TotpDisableRequest(
    @SerialName("factor_id") val factorId: String,
    @SerialName("current_password") val currentPassword: String? = null,
)

@Serializable
data class PasswordRequirementsResponse(
    @SerialName("min_length") val minLength: Int,
    @SerialName("max_length") val maxLength: Int,
    @SerialName("breached_check") val breachedCheck: Boolean,
    @SerialName("rejects_identifier") val rejectsIdentifier: Boolean,
)

// --- administration ----------------------------------------------------------------

@Serializable
data class PageResponse<T>(
    val items: List<T>,
    val total: Long,
    val limit: Int,
    val offset: Long,
)

@Serializable
data class AdminUserResponse(
    val id: String,
    val username: String,
    val email: String,
    @SerialName("email_verified") val emailVerified: Boolean,
    val firstName: String,
    val lastName: String,
    val status: String,
    val roles: List<String>,
    @SerialName("created_at") val createdAt: String,
    @SerialName("updated_at") val updatedAt: String,
)

@Serializable
data class UpdateUserStatusRequest(val status: String)

@Serializable
data class AssignRolesRequest(val roles: List<String>)

@Serializable
data class RoleResponse(
    val name: String,
    val description: String,
    val color: String,
    val permissions: List<String>,
    @SerialName("built_in") val builtIn: Boolean,
)

fun Role.toResponse(): RoleResponse = RoleResponse(
    name = name,
    description = description,
    color = color,
    permissions = permissions.map { it.value }.sorted(),
    builtIn = builtIn,
)

@Serializable
data class UpsertRoleRequest(
    val name: String,
    val description: String = "",
    val color: String = "#5865F2",
    val permissions: List<String> = emptyList(),
)

/**
 * A registered client as the admin UI sees it.
 *
 * `has_secret` rather than the secret or its hash: the plaintext is unrecoverable by design
 * and the hash has no business leaving the database.
 */
@Serializable
data class ClientResponse(
    @SerialName("client_id") val clientId: String,
    val name: String,
    val type: String,
    @SerialName("has_secret") val hasSecret: Boolean,
    @SerialName("secret_rotated_at") val secretRotatedAt: String?,
    @SerialName("redirect_uris") val redirectUris: List<String>,
    val scopes: List<String>,
    @SerialName("grant_types") val grantTypes: List<String>,
    val audiences: List<String>,
    @SerialName("skip_consent") val skipConsent: Boolean,
    val enabled: Boolean,
    @SerialName("created_at") val createdAt: String,
)

fun OAuthClient.toResponse(): ClientResponse = ClientResponse(
    clientId = clientId.value,
    name = name,
    type = type.name,
    hasSecret = secretHash != null,
    secretRotatedAt = secretRotatedAt?.toString(),
    redirectUris = redirectUris.sorted(),
    scopes = allowedScopes.sorted(),
    grantTypes = allowedGrantTypes.map { it.wireValue }.sorted(),
    audiences = audiences.sorted(),
    skipConsent = skipConsent,
    enabled = enabled,
    createdAt = createdAt.toString(),
)

@Serializable
data class RegisterClientRequest(
    @SerialName("client_id") val clientId: String,
    val name: String,
    /** `PUBLIC` or `CONFIDENTIAL`. */
    val type: String = ClientType.PUBLIC.name,
    @SerialName("redirect_uris") val redirectUris: List<String>,
    val scopes: List<String> = listOf("openid", "profile", "email"),
    @SerialName("grant_types") val grantTypes: List<String> = listOf("authorization_code", "refresh_token"),
    val audiences: List<String> = emptyList(),
    @SerialName("skip_consent") val skipConsent: Boolean = false,
)

@Serializable
data class UpdateClientRequest(
    val name: String? = null,
    @SerialName("redirect_uris") val redirectUris: List<String>? = null,
    val scopes: List<String>? = null,
    @SerialName("grant_types") val grantTypes: List<String>? = null,
    val audiences: List<String>? = null,
    @SerialName("skip_consent") val skipConsent: Boolean? = null,
    val enabled: Boolean? = null,
)

/** The one and only time a client secret is returned. */
@Serializable
data class ClientSecretResponse(
    @SerialName("client_id") val clientId: String,
    /** `null` for public clients. */
    val secret: String?,
    @SerialName("rotated_at") val rotatedAt: String,
)

@Serializable
data class AuditRecordResponse(
    val id: String,
    @SerialName("event_type") val eventType: String,
    val outcome: String,
    @SerialName("actor_user_id") val actorUserId: String?,
    @SerialName("subject_user_id") val subjectUserId: String?,
    @SerialName("client_id") val clientId: String?,
    @SerialName("request_id") val requestId: String,
    val metadata: Map<String, String>,
    @SerialName("created_at") val createdAt: String,
)

@Serializable
data class ScopeResponse(
    val name: String,
    val description: String,
    val implicit: Boolean,
)

// --- OAuth protocol ------------------------------------------------------------------

@Serializable
data class TokenEndpointResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("token_type") val tokenType: String,
    @SerialName("expires_in") val expiresIn: Long,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("id_token") val idToken: String? = null,
    val scope: String,
)

@Serializable
data class DiscoveryResponse(
    val issuer: String,
    @SerialName("authorization_endpoint") val authorizationEndpoint: String,
    @SerialName("token_endpoint") val tokenEndpoint: String,
    @SerialName("userinfo_endpoint") val userinfoEndpoint: String,
    @SerialName("jwks_uri") val jwksUri: String,
    @SerialName("revocation_endpoint") val revocationEndpoint: String,
    @SerialName("introspection_endpoint") val introspectionEndpoint: String,
    @SerialName("end_session_endpoint") val endSessionEndpoint: String,
    @SerialName("scopes_supported") val scopesSupported: List<String>,
    @SerialName("response_types_supported") val responseTypesSupported: List<String>,
    @SerialName("grant_types_supported") val grantTypesSupported: List<String>,
    @SerialName("subject_types_supported") val subjectTypesSupported: List<String>,
    @SerialName("id_token_signing_alg_values_supported") val idTokenSigningAlgValuesSupported: List<String>,
    @SerialName("token_endpoint_auth_methods_supported") val tokenEndpointAuthMethodsSupported: List<String>,
    @SerialName("code_challenge_methods_supported") val codeChallengeMethodsSupported: List<String>,
    @SerialName("claims_supported") val claimsSupported: List<String>,
)

@Serializable
data class IntrospectionResponseDto(
    val active: Boolean,
    val scope: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    val username: String? = null,
    @SerialName("token_type") val tokenType: String? = null,
    val exp: Long? = null,
    val iat: Long? = null,
    val sub: String? = null,
    val aud: List<String>? = null,
    val iss: String? = null,
    val jti: String? = null,
)

@Serializable
data class UserInfoDto(
    val sub: String,
    val name: String? = null,
    @SerialName("preferred_username") val preferredUsername: String? = null,
    @SerialName("given_name") val givenName: String? = null,
    @SerialName("family_name") val familyName: String? = null,
    val email: String? = null,
    @SerialName("email_verified") val emailVerified: Boolean? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

/** Consent screen payload for the built-in UI. */
@Serializable
data class ConsentPromptResponse(
    @SerialName("client_id") val clientId: String,
    @SerialName("client_name") val clientName: String,
    val scopes: List<ScopeDescriptionDto>,
    @SerialName("return_to") val returnTo: String,
)

@Serializable
data class ScopeDescriptionDto(val name: String, val description: String)

/** Providers the login UI may offer. */
@Serializable
data class ProviderListResponse(val providers: List<String>)

/** Whoami payload used by the SPA to bootstrap and to obtain a CSRF token. */
@Serializable
data class SessionBootstrapResponse(
    val authenticated: Boolean,
    val user: UserResponse? = null,
    @SerialName("csrf_token") val csrfToken: String,
)
