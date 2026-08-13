import axios from "axios"

/**
 * RFC 9457 problem+json, exactly as `ProblemDetails.kt` emits it.
 *
 * `code` is the stable contract. `title` and `detail` are prose the backend may reword at any
 * time, so nothing in this app is allowed to branch on them (concept §5.6: "Avoid making
 * frontend code depend on human-readable text").
 */
export type ProblemDetails = {
    type: string
    title: string
    status: number
    code: string
    detail: string
    request_id?: string | null
    /** Present on `mfa_required`: the handle to pass to `/v1/auth/mfa/verify`. */
    transaction_id?: string | null
    /** Present on `rate_limited`: seconds to wait before retrying. */
    retry_after?: number | null
    /** Present on `mfa_required`: which factors the user may use. */
    methods?: string[] | null
    expires_at?: string | null
    /** Field-level validation reasons, e.g. `{ password: "too_short" }`. */
    errors?: Record<string, string> | null
}

/** Every stable error code the domain can produce (`AuthError.kt`). */
export const ErrorCode = {
    AUTH_REQUIRED: "auth_required",
    INVALID_CREDENTIALS: "invalid_credentials",
    INVALID_TOKEN: "invalid_token",
    TOKEN_EXPIRED: "token_expired",
    TOKEN_REVOKED: "token_revoked",
    REAUTHENTICATION_REQUIRED: "reauthentication_required",
    MFA_REQUIRED: "mfa_required",
    MFA_INVALID: "mfa_invalid",
    MFA_EXPIRED: "mfa_expired",
    EMAIL_UNVERIFIED: "email_unverified",
    ACCOUNT_SUSPENDED: "account_suspended",
    ACCOUNT_LOCKED: "account_locked",
    ACCOUNT_DISABLED: "account_disabled",
    PASSWORD_RESET_REQUIRED: "password_reset_required",
    PROVIDER_UNAVAILABLE: "provider_unavailable",
    PROVIDER_DENIED: "provider_denied",
    PROVIDER_INVALID_RESPONSE: "provider_invalid_response",
    PROVIDER_LINK_REQUIRED: "provider_link_required",
    PROVIDER_ALREADY_LINKED: "provider_already_linked",
    IDENTITY_ALREADY_LINKED: "identity_already_linked",
    LAST_CREDENTIAL_REMOVAL: "last_credential_removal",
    OAUTH_STATE_INVALID: "oauth_state_invalid",
    OAUTH_NONCE_INVALID: "oauth_nonce_invalid",
    PKCE_VERIFIER_INVALID: "pkce_verifier_invalid",
    REDIRECT_URI_INVALID: "redirect_uri_invalid",
    UNAUTHORIZED_CLIENT: "unauthorized_client",
    INVALID_GRANT: "invalid_grant",
    INVALID_SCOPE: "invalid_scope",
    CONSENT_REQUIRED: "consent_required",
    VALIDATION_FAILED: "validation_failed",
    CONFLICT: "conflict",
    NOT_FOUND: "not_found",
    FORBIDDEN: "forbidden",
    RATE_LIMITED: "rate_limited",
    TEMPORARILY_UNAVAILABLE: "temporarily_unavailable",
    IDEMPOTENCY_CONFLICT: "idempotency_conflict",
    /** Synthetic: the request never reached the server (offline, DNS, CORS, abort). */
    NETWORK: "network_error",
    /** Synthetic: a response we could not parse as problem+json. */
    UNKNOWN: "unknown_error",
    /*
     * Synthetic, raised by `lib/webauthn.ts`. A passkey ceremony fails in the browser, before
     * or instead of a request, but the UI should not need a second error vocabulary for it —
     * so the ceremony reports itself as a [HeliumError] like everything else.
     */
    /** The browser has no WebAuthn API, or the authenticator refused the parameters. */
    WEBAUTHN_UNSUPPORTED: "webauthn_unsupported",
    /** The page is not a secure context; `navigator.credentials` is unavailable off HTTPS. */
    WEBAUTHN_INSECURE_CONTEXT: "webauthn_insecure_context",
    /** The user dismissed the prompt or it timed out — a decision, not a failure. */
    WEBAUTHN_CANCELLED: "webauthn_cancelled",
    /** The authenticator is already enrolled on this account. */
    WEBAUTHN_ALREADY_REGISTERED: "webauthn_already_registered",
    /** The ceremony failed for a reason the browser did not make actionable. */
    WEBAUTHN_FAILED: "webauthn_failed",
} as const

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode]

/**
 * The single error type every API call rejects with.
 *
 * Callers switch on `code`; `message` exists only so an uncaught error still reads sensibly in
 * a console. Nothing user-facing is derived from `message` alone.
 */
export class HeliumError extends Error {
    readonly code: string
    readonly status: number
    readonly problem: ProblemDetails | null
    readonly transactionId: string | null
    readonly methods: string[]
    readonly retryAfter: number | null
    readonly fieldErrors: Record<string, string>

    constructor(problem: ProblemDetails | null, status: number, fallbackCode: string) {
        super(problem?.detail ?? problem?.title ?? fallbackCode)
        this.name = "HeliumError"
        this.problem = problem
        this.status = status
        this.code = problem?.code ?? fallbackCode
        this.transactionId = problem?.transaction_id ?? null
        this.methods = problem?.methods ?? []
        this.retryAfter = problem?.retry_after ?? null
        this.fieldErrors = problem?.errors ?? {}
    }

    is(...codes: string[]): boolean {
        return codes.includes(this.code)
    }
}

function looksLikeProblem(value: unknown): value is ProblemDetails {
    if (typeof value !== "object" || value === null) return false
    const candidate = value as Partial<ProblemDetails>
    return typeof candidate.code === "string" && typeof candidate.status === "number"
}

/** Normalises anything thrown by axios (or by us) into a [HeliumError]. */
export function toHeliumError(error: unknown): HeliumError {
    if (error instanceof HeliumError) return error

    if (axios.isAxiosError(error)) {
        const response = error.response
        if (!response) {
            return new HeliumError(null, 0, ErrorCode.NETWORK)
        }
        if (looksLikeProblem(response.data)) {
            return new HeliumError(response.data, response.status, ErrorCode.UNKNOWN)
        }
        return new HeliumError(null, response.status, ErrorCode.UNKNOWN)
    }

    return new HeliumError(null, 0, ErrorCode.UNKNOWN)
}

/**
 * Human-readable copy for a code.
 *
 * The mapping lives on the client so the wording can be localised and so the UI never has to
 * read `detail`. Unknown codes fall back to the server's `detail`, which is always a safe,
 * non-sensitive sentence.
 */
const MESSAGES: Record<string, string> = {
    [ErrorCode.AUTH_REQUIRED]: "Your session has expired. Please sign in again.",
    [ErrorCode.INVALID_CREDENTIALS]: "Those credentials are not valid.",
    [ErrorCode.INVALID_TOKEN]: "This link is not valid.",
    [ErrorCode.TOKEN_EXPIRED]: "This link has expired. Request a new one.",
    [ErrorCode.TOKEN_REVOKED]: "This link is no longer valid.",
    [ErrorCode.REAUTHENTICATION_REQUIRED]: "Confirm your password to continue.",
    [ErrorCode.MFA_REQUIRED]: "Additional verification is required.",
    [ErrorCode.MFA_INVALID]: "That code is not correct.",
    [ErrorCode.MFA_EXPIRED]: "The verification step expired. Please sign in again.",
    [ErrorCode.EMAIL_UNVERIFIED]: "Verify your email address to continue.",
    [ErrorCode.ACCOUNT_SUSPENDED]: "This account is suspended.",
    [ErrorCode.ACCOUNT_LOCKED]: "This account is temporarily locked.",
    [ErrorCode.ACCOUNT_DISABLED]: "This account is disabled.",
    [ErrorCode.PASSWORD_RESET_REQUIRED]: "You must set a new password to continue.",
    [ErrorCode.PROVIDER_UNAVAILABLE]: "That sign-in provider is unavailable right now.",
    [ErrorCode.PROVIDER_DENIED]: "The provider denied the request.",
    [ErrorCode.PROVIDER_INVALID_RESPONSE]: "The provider returned an unusable response.",
    [ErrorCode.PROVIDER_LINK_REQUIRED]: "Sign in and link this provider to your account first.",
    [ErrorCode.PROVIDER_ALREADY_LINKED]: "That provider is already linked to your account.",
    [ErrorCode.IDENTITY_ALREADY_LINKED]: "That identity belongs to a different account.",
    [ErrorCode.LAST_CREDENTIAL_REMOVAL]: "Keep at least one way to sign in to your account.",
    [ErrorCode.REDIRECT_URI_INVALID]: "The redirect URI is not registered for this client.",
    [ErrorCode.UNAUTHORIZED_CLIENT]: "This client may not perform that request.",
    [ErrorCode.INVALID_SCOPE]: "One or more requested scopes are not permitted.",
    [ErrorCode.VALIDATION_FAILED]: "Please correct the highlighted fields.",
    [ErrorCode.CONFLICT]: "That change conflicts with the current state.",
    [ErrorCode.NOT_FOUND]: "That resource does not exist.",
    [ErrorCode.FORBIDDEN]: "You do not have permission to do that.",
    [ErrorCode.RATE_LIMITED]: "Too many attempts. Please wait and try again.",
    [ErrorCode.TEMPORARILY_UNAVAILABLE]: "The service is temporarily unavailable.",
    [ErrorCode.IDEMPOTENCY_CONFLICT]: "That request was already made with different data.",
    [ErrorCode.NETWORK]: "Could not reach the server. Check your connection.",
    [ErrorCode.UNKNOWN]: "Something went wrong. Please try again.",
    [ErrorCode.WEBAUTHN_UNSUPPORTED]: "This browser cannot use passkeys or security keys.",
    [ErrorCode.WEBAUTHN_INSECURE_CONTEXT]:
        "Passkeys need a secure connection. Open this page over HTTPS and try again.",
    [ErrorCode.WEBAUTHN_CANCELLED]: "The passkey prompt was dismissed or timed out.",
    [ErrorCode.WEBAUTHN_ALREADY_REGISTERED]:
        "That authenticator is already registered on this account.",
    [ErrorCode.WEBAUTHN_FAILED]: "Your device could not complete the passkey request.",
}

export function describeError(error: unknown): string {
    const heliumError = toHeliumError(error)

    if (heliumError.code === ErrorCode.RATE_LIMITED && heliumError.retryAfter) {
        return `Too many attempts. Try again in ${formatRetryAfter(heliumError.retryAfter)}.`
    }

    return MESSAGES[heliumError.code] ?? heliumError.problem?.detail ?? MESSAGES[ErrorCode.UNKNOWN]
}

export function formatRetryAfter(seconds: number): string {
    if (seconds < 60) return `${Math.ceil(seconds)} seconds`
    const minutes = Math.ceil(seconds / 60)
    return minutes === 1 ? "a minute" : `${minutes} minutes`
}

/**
 * Turns `validation_failed` field reasons into form helper text.
 *
 * The backend sends non-sensitive reason tokens (`too_short`, `taken`, ...) and never the
 * rejected value itself, so these are safe to render verbatim.
 */
const FIELD_REASONS: Record<string, string> = {
    too_short: "Too short.",
    too_long: "Too long.",
    breached: "This password has appeared in a known breach.",
    contains_identifier: "Must not contain your username or email.",
    invalid: "Not a valid value.",
    blank: "This field is required.",
    missing: "This field is required.",
    /* `/v1/auth/mfa/verify` accepts exactly one factor, and it has to match the chosen method. */
    ambiguous: "More than one value was sent.",
    method_mismatch: "Does not match the selected verification method.",
    taken: "Already in use.",
    unknown: "Not recognised.",
    unsupported: "Not supported.",
    mismatch: "Does not match.",
}

export function describeFieldError(reason: string): string {
    return FIELD_REASONS[reason] ?? reason.replace(/_/g, " ")
}
