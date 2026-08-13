import { create } from "zustand"
import { authApi } from "../api/auth.ts"
import { accountApi } from "../api/account.ts"
import { setCsrfToken } from "../api/csrf.ts"
import { ErrorCode, toHeliumError } from "../api/problem.ts"
import type {
    LoginRequest,
    MfaMethod,
    MfaSecondFactor,
    MfaVerifyRequest,
    RegisterRequest,
    User,
} from "../api/types.ts"

/**
 * The `mfa_required` challenge, lifted out of the problem response.
 *
 * Login is two-phase: the password buys a short-lived, single-use transaction handle, and the
 * second factor is presented against that handle. The password is never resent.
 */
export type MfaChallenge = {
    transactionId: string
    methods: MfaMethod[]
    expiresAt: string | null
}

const KNOWN_METHODS: MfaMethod[] = ["totp", "recovery_code", "webauthn"]

function parseMethods(methods: string[]): MfaMethod[] {
    const parsed = methods.filter((method): method is MfaMethod =>
        (KNOWN_METHODS as string[]).includes(method),
    )
    // A challenge with no renderable method is still a TOTP challenge in practice; offering
    // nothing would strand the user on a dialog with no inputs.
    return parsed.length > 0 ? parsed : ["totp"]
}

/**
 * Reads an `mfa_required` problem, or `null` when the error is something else.
 *
 * Shared by sign-in and step-up: both are two-phase and both are answered against a one-time
 * handle, so the only thing that differs between them is which endpoint spends it.
 */
export function readMfaChallenge(error: unknown): MfaChallenge | null {
    const heliumError = toHeliumError(error)
    if (!heliumError.is(ErrorCode.MFA_REQUIRED) || !heliumError.transactionId) return null

    return {
        transactionId: heliumError.transactionId,
        methods: parseMethods(heliumError.methods),
        expiresAt: heliumError.problem?.expires_at ?? null,
    }
}

type AuthState = {
    user: User | null
    initialized: boolean
    loading: boolean

    /** Fetches the session and the CSRF token. Must run before any state-changing request. */
    bootstrap: () => Promise<void>
    /** Re-reads `/v1/me` after a profile or MFA change. */
    refresh: () => Promise<void>
    /** Resolves to a challenge when a second factor is required, `null` when signed in. */
    login: (request: LoginRequest) => Promise<MfaChallenge | null>
    completeMfa: (
        transactionId: string,
        factor: MfaSecondFactor,
        rememberDevice?: boolean,
    ) => Promise<void>
    register: (request: RegisterRequest) => Promise<void>
    logout: () => Promise<void>
    /** Drops local state without calling the server, for when the server says it is gone. */
    clearSession: () => void
    setUser: (user: User) => void
}

export const useAuthStore = create<AuthState>((set) => ({
    user: null,
    initialized: false,
    loading: false,

    bootstrap: async () => {
        set({ loading: true })

        try {
            const { data } = await authApi.session()
            // Store the token before anything can issue a write: the request interceptor reads
            // the cookie first, but this covers the moment before the cookie round-trips.
            setCsrfToken(data.csrf_token)

            set({
                user: data.authenticated ? (data.user ?? null) : null,
                initialized: true,
                loading: false,
            })
        } catch {
            set({ user: null, initialized: true, loading: false })
        }
    },

    refresh: async () => {
        try {
            const { data } = await accountApi.me()
            set({ user: data })
        } catch (error) {
            if (toHeliumError(error).is(ErrorCode.AUTH_REQUIRED)) {
                set({ user: null })
            }
        }
    },

    login: async (request) => {
        set({ loading: true })

        try {
            await authApi.login(request)
            // 204: the session cookie and a rotated CSRF token are already set; re-bootstrap to
            // pick both up.
            const { data } = await authApi.session()
            setCsrfToken(data.csrf_token)
            set({ user: data.user ?? null, loading: false })
            return null
        } catch (error) {
            set({ loading: false })

            const challenge = readMfaChallenge(error)
            if (challenge) return challenge
            throw toHeliumError(error)
        }
    },

    completeMfa: async (transactionId, factor, rememberDevice) => {
        set({ loading: true })

        // Built per method rather than spread from one object: the endpoint accepts exactly one
        // of `code` and `webauthn`, and sending the other as `undefined` is not the same thing.
        const request: MfaVerifyRequest =
            factor.method === "webauthn"
                ? {
                      transaction_id: transactionId,
                      method: factor.method,
                      webauthn: factor.assertion,
                      remember_device: rememberDevice,
                  }
                : {
                      transaction_id: transactionId,
                      method: factor.method,
                      code: factor.code,
                      remember_device: rememberDevice,
                  }

        try {
            await authApi.verifyMfa(request)
            const { data } = await authApi.session()
            setCsrfToken(data.csrf_token)
            set({ user: data.user ?? null, loading: false })
        } catch (error) {
            set({ loading: false })
            throw toHeliumError(error)
        }
    },

    register: async (request) => {
        set({ loading: true })

        try {
            // 202 and nothing else, whether or not the address was already taken. No session is
            // issued: the user must verify their email first.
            await authApi.register(request)
            set({ loading: false })
        } catch (error) {
            set({ loading: false })
            throw toHeliumError(error)
        }
    },

    logout: async () => {
        set({ loading: true })

        try {
            await authApi.logout()
        } catch {
            // Logout is idempotent server-side; a failure here must still clear the client.
        } finally {
            setCsrfToken(null)
            set({ user: null, loading: false })
        }
    },

    clearSession: () => {
        setCsrfToken(null)
        set({ user: null })
    },

    setUser: (user) => set({ user }),
}))
