package dev.kamiql.helium.api

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.identity.ExternalIdentity
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions
import dev.kamiql.helium.domain.mfa.WebAuthnRegistrationOptions
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.session.TrustedDevice
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.identity.AuthorizedApp
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

/**
 * Asks for the nonce a challenge-signing method needs before it can be answered.
 *
 * Its own round trip rather than a field on [MfaVerifyRequest]: a passkey assertion cannot be
 * produced without a server-chosen challenge, so the client has to be handed one before it can
 * fill in the verify call at all.
 */
@Serializable
data class MfaChallengeRequest(
    @SerialName("transaction_id") val transactionId: String,
    /** `totp`, `recovery_code` or `webauthn`. */
    val method: String,
)

/** @param webauthn absent for methods that have nothing to sign. */
@Serializable
data class MfaChallengeResponse(
    val method: String,
    val webauthn: WebAuthnAuthenticationOptionsResponse? = null,
)

@Serializable
data class MfaVerifyRequest(
    @SerialName("transaction_id") val transactionId: String,
    /** `totp`, `recovery_code` or `webauthn`. */
    val method: String,
    /**
     * The typed value, for `totp` and `recovery_code`.
     *
     * Optional since passkeys arrived: exactly one of this and [webauthn] carries the answer,
     * and which one is decided by [method]. Kept as the first field a client learns about so
     * every pre-passkey caller still validates unchanged.
     */
    val code: String? = null,
    /** Output of `navigator.credentials.get()`, for `webauthn`. */
    val webauthn: WebAuthnAssertionRequest? = null,
    /**
     * The "don't ask again on this device" checkbox.
     *
     * Defaulted so an older client that omits it never accidentally opts in — the field lowers
     * the assurance of every later login on this browser, and silence is not a request.
     */
    @SerialName("remember_device") val rememberDevice: Boolean = false,
)

/**
 * Reads the answer out of a verify request.
 *
 * The two credential fields are optional on the wire but exactly one of them must be filled in,
 * and it must be the one [method] announced. That is a shape rule, not an authentication
 * decision, so it is settled here and reported as a validation problem: answering a malformed
 * body with `mfa_invalid` would spend one of the transaction's five attempts on a client bug
 * and let a caller probe the server by field layout instead of by secret.
 *
 * A blank [MfaVerifyRequest.code] counts as absent. Forms submit empty strings for untouched
 * inputs, and reading `""` as "present" would make an otherwise valid passkey request ambiguous.
 */
internal fun MfaVerifyRequest.readResponse(method: MfaType): MfaResponseResult {
    val typed = code?.takeIf { it.isNotBlank() }
    if (typed != null && webauthn != null) return MfaResponseResult.Invalid("ambiguous")
    return when (method) {
        MfaType.WEBAUTHN -> webauthn
            ?.let { MfaResponseResult.Valid(it.toDomain()) }
            ?: MfaResponseResult.Invalid(if (typed != null) "method_mismatch" else "missing")

        MfaType.TOTP, MfaType.RECOVERY_CODE -> typed
            ?.let { MfaResponseResult.Valid(MfaResponse.Code(Secret.of(it))) }
            ?: MfaResponseResult.Invalid(if (webauthn != null) "method_mismatch" else "missing")
    }
}

/** @see readResponse */
internal sealed interface MfaResponseResult {
    data class Valid(val response: MfaResponse) : MfaResponseResult

    /** @param reason stable token for the `response` key of a validation problem. */
    data class Invalid(val reason: String) : MfaResponseResult
}

/**
 * Step-up: the password, and nothing else.
 *
 * No identifier field, deliberately. Which account is being re-proved comes from the session
 * cookie; accepting one from the body would turn the step-up endpoint into a second login route
 * — able to authenticate somebody other than the person whose session is about to be refreshed.
 */
@Serializable
data class ReauthenticateRequest(val password: String)

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

/**
 * A remembered device, as the account UI sees it.
 *
 * Enough to recognise a device and revoke it, and nothing else. Both stored hashes stay out:
 * they are the verifiers for a credential that waives the second factor, and an endpoint any
 * signed-in browser can call is a far easier thing to reach than the table they live in.
 */
@Serializable
data class TrustedDeviceResponse(
    val id: String,
    /** Derived from the user agent, so treat it as a hint rather than an identification. */
    val label: String?,
    @SerialName("created_at") val createdAt: String,
    @SerialName("last_used_at") val lastUsedAt: String,
    /** Absolute and non-sliding: the date this device stops being able to skip the challenge. */
    @SerialName("expires_at") val expiresAt: String,
)

fun TrustedDevice.toResponse(): TrustedDeviceResponse = TrustedDeviceResponse(
    id = id.value.toString(),
    label = label,
    createdAt = createdAt.toString(),
    lastUsedAt = lastUsedAt.toString(),
    expiresAt = expiresAt.toString(),
)

/**
 * Outcome of forgetting every device at once.
 *
 * The count exists so the UI can confirm what happened; it is not an error signal, and zero is a
 * perfectly ordinary answer for a user who had nothing remembered.
 */
@Serializable
data class TrustedDevicesRevokedResponse(val revoked: Int)

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
data class AuthorizedScopeResponse(
    val name: String,
    /** Catalogue text, the same sentence the consent screen showed. */
    val description: String,
)

/**
 * An application with access to the account, as the account UI sees it.
 *
 * No token material and no redirect URIs: this answers "who can reach my account and what did I
 * agree to", and everything beyond that belongs to client administration.
 */
@Serializable
data class AuthorizedAppResponse(
    @SerialName("client_id") val clientId: String,
    val name: String,
    val scopes: List<AuthorizedScopeResponse>,
    @SerialName("authorized_at") val authorizedAt: String,
    /** `null` when the client currently holds no usable refresh token. */
    @SerialName("last_authorized_at") val lastAuthorizedAt: String?,
    /** Live refresh-token families. Zero means a standing consent with nothing active behind it. */
    @SerialName("active_grants") val activeGrants: Int,
    /** `false` marks a first-party client that was registered to skip the consent screen. */
    val consented: Boolean,
)

fun AuthorizedApp.toResponse(): AuthorizedAppResponse = AuthorizedAppResponse(
    clientId = clientId.value,
    name = name,
    scopes = scopes.map { AuthorizedScopeResponse(it.name, it.description) },
    authorizedAt = authorizedAt.toString(),
    lastAuthorizedAt = lastAuthorizedAt?.toString(),
    activeGrants = activeGrants,
    consented = consented,
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

// --- WebAuthn ------------------------------------------------------------------
//
// Every binary field below is base64url, in both directions. The bytes are decoded by the
// WebAuthn adapter and nowhere else, so nothing on this boundary needs a CBOR or COSE parser —
// and none of these values is ever logged: a credential id identifies an authenticator, and
// client data, signatures and challenges are the inputs an attacker would need to forge one.

@Serializable
data class WebAuthnEnrollRequest(
    /** What the user calls this authenticator. `null` lets the flow pick a default. */
    val label: String? = null,
)

/** `PublicKeyCredentialCreationOptions`, as the browser needs them. */
@Serializable
data class WebAuthnRegistrationOptionsResponse(
    val challenge: String,
    @SerialName("rp_id") val rpId: String,
    @SerialName("rp_name") val rpName: String,
    @SerialName("user_handle") val userHandle: String,
    @SerialName("user_name") val userName: String,
    @SerialName("user_display_name") val userDisplayName: String,
    /** COSE algorithm identifiers, in the server's order of preference. */
    val algorithms: List<Long>,
    @SerialName("exclude_credential_ids") val excludeCredentialIds: List<String>,
    @SerialName("user_verification") val userVerification: String,
    @SerialName("timeout_ms") val timeoutMs: Long,
)

fun WebAuthnRegistrationOptions.toResponse(): WebAuthnRegistrationOptionsResponse =
    WebAuthnRegistrationOptionsResponse(
        challenge = challenge,
        rpId = rpId,
        rpName = rpName,
        userHandle = userHandle,
        userName = userName,
        userDisplayName = userDisplayName,
        algorithms = algorithms,
        excludeCredentialIds = excludeCredentialIds,
        // Lowercase because that is the spelling the WebAuthn API itself takes; a client should
        // be able to hand this straight to `navigator.credentials` without a lookup table.
        userVerification = userVerification.name.lowercase(),
        timeoutMs = timeout.toMillis(),
    )

/** `PublicKeyCredentialRequestOptions`, as the browser needs them. */
@Serializable
data class WebAuthnAuthenticationOptionsResponse(
    val challenge: String,
    @SerialName("rp_id") val rpId: String,
    @SerialName("allow_credential_ids") val allowCredentialIds: List<String>,
    @SerialName("user_verification") val userVerification: String,
    @SerialName("timeout_ms") val timeoutMs: Long,
)

fun WebAuthnAuthenticationOptions.toResponse(): WebAuthnAuthenticationOptionsResponse =
    WebAuthnAuthenticationOptionsResponse(
        challenge = challenge,
        rpId = rpId,
        allowCredentialIds = allowCredentialIds,
        userVerification = userVerification.name.lowercase(),
        timeoutMs = timeout.toMillis(),
    )

/**
 * The factor id issued by `enroll`, plus the authenticator's answer.
 *
 * [label] is repeated here rather than only being taken at `enroll` so a user who was shown a
 * name-your-key prompt *after* touching the authenticator can still have it recorded.
 */
@Serializable
data class WebAuthnConfirmRequest(
    @SerialName("factor_id") val factorId: String,
    val label: String? = null,
    @SerialName("credential_id") val credentialId: String,
    @SerialName("client_data_json") val clientDataJson: String,
    @SerialName("attestation_object") val attestationObject: String,
    /** Authenticator-reported transports (`usb`, `nfc`, `internal`, …). Advisory only. */
    val transports: List<String> = emptyList(),
)

fun WebAuthnConfirmRequest.toDomain(): MfaResponse.WebAuthnRegistration =
    MfaResponse.WebAuthnRegistration(
        credentialId = credentialId,
        clientDataJson = clientDataJson,
        attestationObject = attestationObject,
        transports = transports,
    )

@Serializable
data class WebAuthnEnrollResponse(
    @SerialName("factor_id") val factorId: String,
    val options: WebAuthnRegistrationOptionsResponse,
)

/**
 * @param recoveryCodes present only when this passkey is the user's first factor. Regenerating
 *        them for every enrollment would silently invalidate the codes a user already wrote down.
 */
@Serializable
data class WebAuthnConfirmResponse(
    @SerialName("factor_id") val factorId: String,
    @SerialName("recovery_codes") val recoveryCodes: List<String>? = null,
)

@Serializable
data class WebAuthnRemoveRequest(
    @SerialName("factor_id") val factorId: String,
    @SerialName("current_password") val currentPassword: String? = null,
)

/**
 * Output of `navigator.credentials.get()`.
 *
 * [userHandle] is absent for a non-discoverable credential, which is the ordinary case for a
 * second factor: the MFA transaction already says who is signing in.
 */
@Serializable
data class WebAuthnAssertionRequest(
    @SerialName("credential_id") val credentialId: String,
    @SerialName("client_data_json") val clientDataJson: String,
    @SerialName("authenticator_data") val authenticatorData: String,
    val signature: String,
    @SerialName("user_handle") val userHandle: String? = null,
)

fun WebAuthnAssertionRequest.toDomain(): MfaResponse.WebAuthnAssertion =
    MfaResponse.WebAuthnAssertion(
        credentialId = credentialId,
        clientDataJson = clientDataJson,
        authenticatorData = authenticatorData,
        signature = signature,
        userHandle = userHandle,
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
    /** Protocol-level scope. Cannot be edited or deleted; a role editor should show it read-only. */
    @SerialName("built_in") val builtIn: Boolean,
)

fun Scope.toResponse(): ScopeResponse = ScopeResponse(
    name = name,
    description = description,
    implicit = implicit,
    builtIn = builtIn,
)

/** Body of `PUT /v1/admin/scopes/{name}`. The name comes from the path, not from here. */
@Serializable
data class UpsertScopeRequest(
    /** Shown verbatim on the consent screen, so it must read as a sentence to a non-technical user. */
    val description: String,
    /**
     * Grant without showing it on the consent screen.
     *
     * Only appropriate for a scope that carries no user-visible authority of its own — `openid`
     * is the reason this exists. Defaults to false: a scope a user never sees is a scope they
     * never declined.
     */
    val implicit: Boolean = false,
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
    // Optional per OIDC Discovery §3, and omitted from the response when null because
    // `explicitNulls = false`. HeliumID has no RP-initiated logout endpoint to name.
    @SerialName("end_session_endpoint") val endSessionEndpoint: String? = null,
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
    val allow: List<String> = listOf("GET")
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
