import axios, { type AxiosResponse, type InternalAxiosRequestConfig } from "axios"
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

/**
 * Set on a config once it has been replayed after a step-up.
 *
 * A replay that is answered with `reauthentication_required` again is not a request that needs
 * confirming — it is a loop, and without this flag it is an unbounded one.
 */
const REPLAYED = Symbol("helium.stepUpReplayed")

type ReplayableConfig = InternalAxiosRequestConfig & { [REPLAYED]?: boolean }

/** Reactions the app registers once, so this module never imports a store or the router. */
type GlobalHandlers = {
    /** `auth_required` — the session is gone; drop local state and send the user to /login. */
    onSessionLost: () => void
    /** `email_unverified` — surface the resend UI wherever the app chooses to show it. */
    onEmailUnverified: () => void
    /**
     * `reauthentication_required` — the user must confirm their password again.
     *
     * Receives the request that provoked the challenge and answers with the promise the caller
     * keeps awaiting, so a confirmed step-up completes the action the user already asked for
     * instead of telling them to perform it again.
     */
    onReauthenticationRequired: (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
}

let handlers: GlobalHandlers = {
    onSessionLost: () => {},
    onEmailUnverified: () => {},
    onReauthenticationRequired: () => Promise.reject(new Error("no step-up handler registered")),
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
            case ErrorCode.REAUTHENTICATION_REQUIRED: {
                const config = (error as { config?: ReplayableConfig }).config
                if (config && config[REPLAYED] !== true) {
                    config[REPLAYED] = true

                    // The only branch here that does not reject: the caller's promise is handed
                    // to the step-up prompt and settles from the replayed request.
                    return handlers.onReauthenticationRequired(config)
                }
                break
            }
            default:
                break
        }

        return Promise.reject(heliumError)
    },
)
