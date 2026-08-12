import axios, { type InternalAxiosRequestConfig } from "axios"
import { useRequestStore } from "../stores/request.store.ts"
import { currentCsrfToken } from "./csrf.ts"
import { ErrorCode, toHeliumError, type HeliumError } from "./problem.ts"

/**
 * Caddy proxies `/api/*` to the backend and strips the `/api` prefix, so `baseURL: "/api"`
 * plus a path of `/v1/auth/login` reaches `POST /v1/auth/login` on the identity server.
 *
 * `withCredentials` is required: the browser session is a cookie, not a bearer token.
 */
export const api = axios.create({
    baseURL: "/api",
    withCredentials: true,
})

const SAFE_METHODS = new Set(["get", "head", "options"])

/** Reactions the app registers once, so this module never imports a store or the router. */
type GlobalHandlers = {
    /** `auth_required` — the session is gone; drop local state and send the user to /login. */
    onSessionLost: () => void
    /** `email_unverified` — surface the resend UI wherever the app chooses to show it. */
    onEmailUnverified: () => void
    /** `reauthentication_required` — the user must confirm their password again. */
    onReauthenticationRequired: () => void
}

let handlers: GlobalHandlers = {
    onSessionLost: () => {},
    onEmailUnverified: () => {},
    onReauthenticationRequired: () => {},
}

export function registerApiHandlers(next: Partial<GlobalHandlers>): void {
    handlers = { ...handlers, ...next }
}

api.interceptors.request.use(
    (config: InternalAxiosRequestConfig) => {
        useRequestStore.getState().startRequest()

        // Every state-changing request carries the double-submit token. Safe methods do not
        // need it and the backend does not check it for them.
        const method = (config.method ?? "get").toLowerCase()
        if (!SAFE_METHODS.has(method)) {
            const token = currentCsrfToken()
            if (token) {
                config.headers.set("X-CSRF-Token", token)
            }
        }

        return config
    },
    (error: unknown) => {
        useRequestStore.getState().finishRequest()

        return Promise.reject(toHeliumError(error))
    },
)

/**
 * One place where a problem+json `code` becomes an action (concept §5.6).
 *
 * Everything that is *global* happens here; anything a specific screen must react to
 * (`mfa_required`, `validation_failed`, ...) is left on the rejected [HeliumError] for the
 * caller. No branch in this file — or anywhere else — looks at `title` or `detail`.
 */
api.interceptors.response.use(
    (response) => {
        useRequestStore.getState().finishRequest()

        return response
    },
    (error: unknown) => {
        useRequestStore.getState().finishRequest()

        const heliumError: HeliumError = toHeliumError(error)

        switch (heliumError.code) {
            case ErrorCode.AUTH_REQUIRED:
            case ErrorCode.TOKEN_REVOKED:
                handlers.onSessionLost()
                break
            case ErrorCode.EMAIL_UNVERIFIED:
                handlers.onEmailUnverified()
                break
            case ErrorCode.REAUTHENTICATION_REQUIRED:
                handlers.onReauthenticationRequired()
                break
            default:
                break
        }

        return Promise.reject(heliumError)
    },
)
