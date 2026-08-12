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

export type MfaMethod = "totp" | "recovery_code" | "webauthn"

export type MfaVerifyRequest = {
    transaction_id: string
    method: MfaMethod
    code: string
}

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

export type LinkedProvider = {
    provider: string
    email: string | null
    linked_at: string
    last_login_at: string | null
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
