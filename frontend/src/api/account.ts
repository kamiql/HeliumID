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
    TotpConfirmRequest,
    TotpDisableRequest,
    TotpEnrollment,
    UpdateProfileRequest,
    User,
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

    // --- MFA ------------------------------------------------------------------

    factors: () => api.get<MfaFactor[]>("/v1/me/mfa"),

    /** Returns the shared secret exactly once; it is not re-fetchable afterwards. */
    enrollTotp: () => api.post<TotpEnrollment>("/v1/me/mfa/totp/enroll"),

    /** The only response that ever carries recovery codes. */
    confirmTotp: (request: TotpConfirmRequest) =>
        api.post<RecoveryCodes>("/v1/me/mfa/totp/confirm", request),

    disableTotp: (request: TotpDisableRequest) => api.post<void>("/v1/me/mfa/totp/disable", request),

    regenerateRecoveryCodes: () => api.post<RecoveryCodes>("/v1/me/mfa/recovery-codes"),

    // --- linked providers -------------------------------------------------------

    linkedProviders: () => api.get<LinkedProvider[]>("/v1/me/providers"),

    unlinkProvider: (provider: string) =>
        api.delete<void>(`/v1/me/providers/${encodeURIComponent(provider)}`),
}
