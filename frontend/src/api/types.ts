/**
 * Wire types for the HeliumID `/v1` API.
 *
 * These mirror `backend/api-http/src/main/kotlin/dev/kamiql/helium/api/Dto.kt` field for field,
 * including the exact `@SerialName` casing. Most fields are snake_case; a handful (`firstName`,
 * `lastName`, `username`, `password`, ...) carry no `@SerialName` on the backend and therefore
 * stay camelCase on the wire. Do not "tidy" the casing here — it is the contract.
 */

// --- shared -------------------------------------------------------------------

export type Page<T> = {
    items: T[]
    total: number
    limit: number
    offset: number
}

export type AcceptedResponse = {
    status: string
}

// --- authentication -----------------------------------------------------------

export type RegisterRequest = {
    username: string
    email: string
    password: string
    firstName: string
    lastName: string
}

export type LoginRequest = {
    /** Username or email — the backend accepts either. */
    identifier: string
    password: string
}

/**
 * `POST /v1/auth/reauthenticate` — step-up for the session the browser already holds.
 *
 * No identifier, unlike [LoginRequest]: the account being re-proved is the one behind the
 * session cookie, and letting the body name a different one would make this a login route that
 * happens not to hand out a cookie.
 */
export type ReauthenticateRequest = {
    password: string
}

export type MfaMethod = "totp" | "recovery_code" | "webauthn"

/**
 * How hard the authenticator must prove the *user* is present, as opposed to the key.
 *
 * The server decides this per ceremony; the client only passes it through to the browser.
 */
export type WebauthnUserVerification = "required" | "preferred" | "discouraged"

/** `POST /v1/auth/mfa/challenge` — fetches the material for one method of a live transaction. */
export type MfaChallengeRequest = {
    transaction_id: string
    method: MfaMethod
}

/** Authentication ceremony options. Binary fields are base64url, never standard base64. */
export type WebauthnAssertionOptions = {
    challenge: string
    rp_id: string
    /** Credentials enrolled on this account. Empty means "any", which we never ask for. */
    allow_credential_ids: string[]
    user_verification: WebauthnUserVerification
    timeout_ms: number
}

/**
 * `webauthn` is **absent** for methods that need no server-issued challenge, i.e. all but one.
 *
 * Optional rather than nullable throughout: the backend serialises with `explicitNulls = false`,
 * so an empty field is a missing key and never a `null` to compare against.
 */
export type MfaChallengeResponse = {
    method: string
    webauthn?: WebauthnAssertionOptions
}

/** What the authenticator signed, base64url-encoded for the wire. */
export type WebauthnAssertion = {
    credential_id: string
    client_data_json: string
    authenticator_data: string
    signature: string
    /** Only present for discoverable credentials; a second factor usually omits it. */
    user_handle: string | null
}

export type MfaVerifyRequest = {
    transaction_id: string
    method: MfaMethod
    /** Exactly one of `code` and `webauthn` is sent, and it matches `method`. */
    code?: string
    webauthn?: WebauthnAssertion
    /**
     * Opt-in. On success the server sets its own `HttpOnly` device cookie; the client never
     * sees or keeps a token of its own.
     */
    remember_device?: boolean
}

/**
 * The second factor as the UI collects it, before it becomes an [MfaVerifyRequest].
 *
 * A union rather than one type with two optional payloads: the endpoint accepts exactly one of
 * `code` and `webauthn`, and this is the shape that makes sending both unrepresentable.
 */
export type MfaSecondFactor =
    | { method: "totp" | "recovery_code"; code: string }
    | { method: "webauthn"; assertion: WebauthnAssertion }

export type TokenRequestBody = {
    token: string
}

export type EmailRequest = {
    email: string
}

export type PasswordResetCompleteRequest = {
    token: string
    new_password: string
}

export type PasswordRequirements = {
    min_length: number
    max_length: number
    breached_check: boolean
    rejects_identifier: boolean
}

export type ProviderListResponse = {
    providers: string[]
}

export type UserStatus =
    | "PENDING_EMAIL_VERIFICATION"
    | "ACTIVE"
    | "SUSPENDED"
    | "LOCKED"
    | "DELETED"

export type User = {
    id: string
    username: string
    email: string
    email_verified: boolean
    firstName: string
    lastName: string
    status: UserStatus | string
    roles: string[]
    permissions: string[]
    mfa_enabled: boolean
    created_at: string
}

/** `GET /v1/auth/session` — whoami plus the CSRF token the SPA must echo back. */
export type SessionBootstrap = {
    authenticated: boolean
    user?: User | null
    csrf_token: string
}

// --- account ------------------------------------------------------------------

export type ChangePasswordRequest = {
    current_password: string
    new_password: string
}

export type EmailChangeRequest = {
    new_email: string
    current_password: string
}

export type UpdateProfileRequest = {
    username?: string | null
    firstName?: string | null
    lastName?: string | null
}

export type DeleteAccountRequest = {
    current_password?: string | null
}

export type SessionInfo = {
    id: string
    device: string | null
    created_at: string
    last_seen_at: string
    expires_at: string
    /** True for the session issuing the request, so the UI can label it. */
    current: boolean
}

export type TrustedDevice = {
    id: string
    /** Derived from the user agent, so a hint rather than an identification. */
    label: string | null
    created_at: string
    last_used_at: string
    /** Absolute and non-sliding: when the device stops being able to skip the challenge. */
    expires_at: string
}

/** `revoked` is a count for the confirmation copy, not a success signal — zero is normal. */
export type TrustedDevicesRevokedResponse = {
    revoked: number
}

export type LinkedProvider = {
    provider: string
    email: string | null
    linked_at: string
    last_login_at: string | null
}

export type AuthorizedScope = {
    name: string
    /** Catalogue text — the same sentence the consent screen showed. */
    description: string
}

/**
 * An application holding access to the account.
 *
 * The other direction from {@link LinkedProvider}: those are what you sign in *with*, these are
 * the OAuth clients that can reach your account.
 */
export type AuthorizedApp = {
    client_id: string
    name: string
    scopes: AuthorizedScope[]
    authorized_at: string
    /** `null` when the app currently holds no usable refresh token. */
    last_authorized_at: string | null
    /** Live refresh-token families; zero means a standing consent with nothing active behind it. */
    active_grants: number
    /** `false` marks a first-party client registered to skip the consent screen. */
    consented: boolean
}

export type MfaFactorStatus = "PENDING" | "ACTIVE" | "REVOKED"

export type MfaFactor = {
    id: string
    /** `totp`, `webauthn` or `recovery_code`. */
    type: string
    label: string
    status: MfaFactorStatus | string
    created_at: string
    last_used_at: string | null
}

/** The only response that ever carries a TOTP secret. It is not re-fetchable. */
export type TotpEnrollment = {
    factor_id: string
    secret: string
    otpauth_uri: string
}

/** Recovery codes, returned once at enrollment or regeneration and never again. */
export type RecoveryCodes = {
    codes: string[]
}

export type TotpConfirmRequest = {
    factor_id: string
    code: string
}

export type TotpDisableRequest = {
    factor_id: string
    current_password?: string | null
}

/** The body is required even when there is nothing to say — an empty request is rejected. */
export type WebauthnEnrollRequest = {
    /** Optional nickname for the key. `null` lets the server pick something generic. */
    label: string | null
}

/** Registration ceremony options. Binary fields are base64url, never standard base64. */
export type WebauthnEnrollOptions = {
    challenge: string
    rp_id: string
    rp_name: string
    user_handle: string
    user_name: string
    user_display_name: string
    /** COSE algorithm identifiers, most preferred first — e.g. `-7` for ES256. */
    algorithms: number[]
    /** Credentials already enrolled, so an authenticator can refuse to register twice. */
    exclude_credential_ids: string[]
    user_verification: WebauthnUserVerification
    timeout_ms: number
}

/** The factor exists as `PENDING` from here; it only counts once the ceremony is confirmed. */
export type WebauthnEnrollment = {
    factor_id: string
    options: WebauthnEnrollOptions
}

/** What the authenticator produced during registration, base64url-encoded for the wire. */
export type WebauthnRegistration = {
    credential_id: string
    client_data_json: string
    attestation_object: string
    /** From `getTransports()`; empty when the browser does not report them. */
    transports: string[]
}

export type WebauthnConfirmRequest = WebauthnRegistration & {
    factor_id: string
    label: string | null
}

/**
 * `recovery_codes` is present only when this passkey is what turned two-factor on — the same
 * once-and-never-again payload TOTP enrollment returns. Absent, not `null`, otherwise.
 */
export type WebauthnConfirmResponse = {
    factor_id: string
    recovery_codes?: string[]
}

export type WebauthnRemoveRequest = {
    factor_id: string
    current_password?: string | null
}

// --- administration -----------------------------------------------------------

export type AdminUser = {
    id: string
    username: string
    email: string
    email_verified: boolean
    firstName: string
    lastName: string
    status: UserStatus | string
    roles: string[]
    created_at: string
    updated_at: string
}

export type AdminUserQuery = {
    q?: string
    status?: string
    role?: string
    limit?: number
    offset?: number
}

export type UpdateUserStatusRequest = {
    status: string
}

export type AssignRolesRequest = {
    roles: string[]
}

export type RevokeSessionsResponse = {
    revoked: number
}

export type Role = {
    name: string
    description: string
    color: string
    permissions: string[]
    built_in: boolean
}

export type UpsertRoleRequest = {
    name: string
    description?: string
    color?: string
    permissions?: string[]
}

export type ClientType = "PUBLIC" | "CONFIDENTIAL"

export type GrantType = "authorization_code" | "refresh_token" | "client_credentials"

export type OAuthClient = {
    client_id: string
    name: string
    type: ClientType | string
    /** The plaintext secret is unrecoverable by design; only its existence is exposed. */
    has_secret: boolean
    secret_rotated_at: string | null
    redirect_uris: string[]
    scopes: string[]
    grant_types: string[]
    audiences: string[]
    skip_consent: boolean
    enabled: boolean
    created_at: string
}

export type RegisterClientRequest = {
    client_id: string
    name: string
    type: ClientType
    redirect_uris: string[]
    scopes: string[]
    grant_types: GrantType[]
    audiences: string[]
    skip_consent: boolean
}

export type UpdateClientRequest = {
    name?: string
    redirect_uris?: string[]
    scopes?: string[]
    grant_types?: GrantType[]
    audiences?: string[]
    skip_consent?: boolean
    enabled?: boolean
}

/** The one and only time a client secret is returned. */
export type ClientSecret = {
    client_id: string
    /** `null` for public clients — they have no secret at all. */
    secret: string | null
    rotated_at: string
}

export type Scope = {
    name: string
    description: string
    implicit: boolean
}

export type AuditRecord = {
    id: string
    event_type: string
    outcome: string
    actor_user_id: string | null
    subject_user_id: string | null
    client_id: string | null
    request_id: string
    metadata: Record<string, string>
    created_at: string
}

export type AuditQuery = {
    user_id?: string
    event_type?: string
    limit?: number
    offset?: number
}

// --- OAuth protocol -----------------------------------------------------------

export type ScopeDescription = {
    name: string
    description: string
}

export type ConsentPrompt = {
    client_id: string
    client_name: string
    scopes: ScopeDescription[]
    return_to: string
}
