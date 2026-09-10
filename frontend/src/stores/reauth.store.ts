import type { AxiosResponse, InternalAxiosRequestConfig } from "axios"
import { create } from "zustand"
import { ErrorCode, HeliumError } from "../api/problem.ts"

/** The request that provoked the step-up, parked until the user has confirmed. */
type PendingRequest = {
    config: InternalAxiosRequestConfig
    resolve: (response: AxiosResponse) => void
    reject: (error: unknown) => void
}

type ReauthState = {
    open: boolean
    pending: PendingRequest | null
    /**
     * Opened by the axios interceptor when the server answers `reauthentication_required`.
     *
     * Returns the promise the original caller is still awaiting: it settles from the replay
     * once the step-up succeeds, or rejects if the prompt is dismissed.
     */
    request: (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>
    /** Step-up succeeded: hand the parked request back for replay. */
    takePending: () => PendingRequest | null
    close: () => void
}

/**
 * Freshness is measured from the session's `authenticatedAt`, and `POST /v1/auth/reauthenticate`
 * is what moves it — password first, second factor after, the same bar as signing in but without
 * a session coming out of it. Replaying `/login` here, which is what this used to do, minted one
 * per confirmation and made the account's device list unreadable.
 *
 * The store also parks the request that triggered the prompt. Without it the caller's promise
 * rejected and the user had to perform the whole action a second time, retyping a password or
 * an email address into a form that had already been submitted once — and re-deciding an
 * irreversible one like account deletion. The action the user already took is the thing being
 * confirmed, so it is what gets sent; a step-up that discards it is asking about nothing.
 */
export const useReauthStore = create<ReauthState>((set, get) => ({
    open: false,
    pending: null,

    request: (config) => {
        // A second challenge while one is already parked means two requests raced the same
        // stale clock. The prompt confirms one identity, not one request, so the later caller
        // waits for the same outcome rather than opening a second dialog over the first.
        const existing = get().pending
        if (existing) {
            return new Promise<AxiosResponse>((_, reject) => {
                reject(new HeliumError(null, 401, ErrorCode.REAUTHENTICATION_REQUIRED))
            })
        }

        return new Promise<AxiosResponse>((resolve, reject) => {
            set({ open: true, pending: { config, resolve, reject } })
        })
    },

    takePending: () => {
        const pending = get().pending
        set({ open: false, pending: null })
        return pending
    },

    close: () => {
        // Dismissing the prompt is a decision about the action, not just about the dialog: the
        // caller is still awaiting, so it is told the step-up did not happen. Rejecting with the
        // error the server actually sent keeps `catch` blocks that already handle it working.
        const pending = get().pending
        set({ open: false, pending: null })
        pending?.reject(new HeliumError(null, 401, ErrorCode.REAUTHENTICATION_REQUIRED))
    },
}))
