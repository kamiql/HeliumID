import { api } from "./axios.ts"
import type {
    AcceptedResponse,
    EmailRequest,
    LoginRequest,
    MfaVerifyRequest,
    PasswordRequirements,
    PasswordResetCompleteRequest,
    ProviderListResponse,
    RegisterRequest,
    SessionBootstrap,
    TokenRequestBody,
} from "./types.ts"

/**
 * `/v1/auth` — first-party authentication.
 *
 * Login is deliberately two-phase. `POST /login` answers `204` when the password alone is
 * enough, and `401 { code: "mfa_required", transaction_id, methods }` when it is not. The
 * second factor is then submitted against that one-time transaction handle rather than by
 * replaying the password, so the password never has to be held across the challenge.
 */
export const authApi = {
    /**
     * Whoami plus a fresh CSRF token. Always `200`, even when anonymous — a `401` on every
     * page load would be indistinguishable from a real failure.
     */
    session: () => api.get<SessionBootstrap>("/v1/auth/session"),

    passwordRequirements: () => api.get<PasswordRequirements>("/v1/auth/password-requirements"),

    register: (request: RegisterRequest) =>
        api.post<AcceptedResponse>("/v1/auth/register", request),

    /** `204` on success; rejects with `mfa_required` when a second factor is needed. */
    login: (request: LoginRequest) => api.post<void>("/v1/auth/login", request),

    verifyMfa: (request: MfaVerifyRequest) => api.post<void>("/v1/auth/mfa/verify", request),

    logout: () => api.post<void>("/v1/auth/logout"),

    verifyEmail: (token: string) =>
        api.post<void>("/v1/auth/email/verify", { token } satisfies TokenRequestBody),

    resendVerification: (email: string) =>
        api.post<AcceptedResponse>("/v1/auth/email/resend", { email } satisfies EmailRequest),

    /** Always accepted, whether or not the address exists — never leak account existence. */
    requestPasswordReset: (email: string) =>
        api.post<AcceptedResponse>("/v1/auth/password-reset/request", {
            email,
        } satisfies EmailRequest),

    /**
     * Completing a reset does **not** sign the user in: proving mailbox control is not the
     * same as proving identity. The UI sends them to /login afterwards.
     */
    completePasswordReset: (request: PasswordResetCompleteRequest) =>
        api.post<void>("/v1/auth/password-reset/complete", request),

    providers: () => api.get<ProviderListResponse>("/v1/auth/providers"),
}

/**
 * Starts a provider round trip with a full-page navigation.
 *
 * This cannot be an XHR: the backend answers with a `302` to the provider's authorization
 * endpoint and sets a short-lived `HttpOnly` state cookie that must ride along on the callback.
 *
 * @param intent `"link"` attaches the provider to the signed-in account instead of signing in.
 */
export function startProviderFlow(provider: string, intent?: "link"): void {
    const query = intent ? "?intent=link" : ""
    window.location.assign(`/api/v1/auth/providers/${encodeURIComponent(provider)}/start${query}`)
}
