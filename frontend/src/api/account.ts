import { api } from "./axios.ts"
import type {
    AcceptedResponse,
    ChangePasswordRequest,
    DeleteAccountRequest,
    EmailChangeRequest,
    LinkedProvider,
    MfaFactor,
    RecoveryCodes,
    SessionInfo,
    TokenRequestBody,
    TrustedDevice,
    TrustedDevicesRevokedResponse,
    TotpConfirmRequest,
    TotpDisableRequest,
    TotpEnrollment,
    UpdateProfileRequest,
    User,
    WebauthnConfirmRequest,
    WebauthnConfirmResponse,
    WebauthnEnrollment,
    WebauthnEnrollRequest,
    WebauthnRemoveRequest,
} from "./types.ts"

/** `/v1/me` — account self-service. */
export const accountApi = {
    me: () => api.get<User>("/v1/me"),

    updateProfile: (request: UpdateProfileRequest) => api.put<User>("/v1/me", request),

    changePassword: (request: ChangePasswordRequest) => api.put<void>("/v1/me/password", request),

    /**
     * Step one of a two-step email change: the new address is only recorded once the token
     * mailed *to it* comes back, so a hijacked session cannot silently move the address.
     */
    requestEmailChange: (request: EmailChangeRequest) =>
        api.post<AcceptedResponse>("/v1/me/email-change", request),

    confirmEmailChange: (token: string) =>
        api.post<void>("/v1/me/email-change/confirm", { token } satisfies TokenRequestBody),

    deleteAccount: (request: DeleteAccountRequest) => api.post<void>("/v1/me/delete", request),

    // --- sessions -------------------------------------------------------------

    sessions: () => api.get<SessionInfo[]>("/v1/me/sessions"),

    revokeSession: (sessionId: string) =>
        api.delete<void>(`/v1/me/sessions/${encodeURIComponent(sessionId)}`),

    // --- trusted devices ---------------------------------------------------------

    trustedDevices: () => api.get<TrustedDevice[]>("/v1/me/trusted-devices"),

    /** Revoking is the only way back: the device otherwise skips MFA until it expires. */
    revokeTrustedDevice: (deviceId: string) =>
        api.delete<void>(`/v1/me/trusted-devices/${encodeURIComponent(deviceId)}`),

    /** Includes the caller's own device — the server drops this browser's cookie too. */
    revokeAllTrustedDevices: () =>
        api.delete<TrustedDevicesRevokedResponse>("/v1/me/trusted-devices"),

    // --- MFA ------------------------------------------------------------------

    factors: () => api.get<MfaFactor[]>("/v1/me/mfa"),

    /** Returns the shared secret exactly once; it is not re-fetchable afterwards. */
    enrollTotp: () => api.post<TotpEnrollment>("/v1/me/mfa/totp/enroll"),

    /** The only response that ever carries recovery codes. */
    confirmTotp: (request: TotpConfirmRequest) =>
        api.post<RecoveryCodes>("/v1/me/mfa/totp/confirm", request),

    disableTotp: (request: TotpDisableRequest) => api.post<void>("/v1/me/mfa/totp/disable", request),

    regenerateRecoveryCodes: () => api.post<RecoveryCodes>("/v1/me/mfa/recovery-codes"),

    // --- passkeys ---------------------------------------------------------------

    /**
     * Reserves a `PENDING` factor and returns the registration options for it. The credential
     * only exists once [confirmWebauthn] hands the attestation back for the same `factor_id`.
     */
    enrollWebauthn: (request: WebauthnEnrollRequest) =>
        api.post<WebauthnEnrollment>("/v1/me/mfa/webauthn/enroll", request),

    /** Carries recovery codes when this passkey is what turned two-factor on, `null` otherwise. */
    confirmWebauthn: (request: WebauthnConfirmRequest) =>
        api.post<WebauthnConfirmResponse>("/v1/me/mfa/webauthn/confirm", request),

    /** A `POST`, not a `DELETE`: removal carries a password in the body. */
    removeWebauthn: (request: WebauthnRemoveRequest) =>
        api.post<void>("/v1/me/mfa/webauthn/remove", request),

    // --- linked providers -------------------------------------------------------

    linkedProviders: () => api.get<LinkedProvider[]>("/v1/me/providers"),

    unlinkProvider: (provider: string) =>
        api.delete<void>(`/v1/me/providers/${encodeURIComponent(provider)}`),
}
