import { create } from "zustand"

type ReauthState = {
    open: boolean
    /** Opened by the axios interceptor when the server answers `reauthentication_required`. */
    request: () => void
    close: () => void
}

/**
 * Freshness is measured from the session's `authenticatedAt`, and `POST /v1/auth/reauthenticate`
 * is what moves it — password first, second factor after, the same bar as signing in but without
 * a session coming out of it. Replaying `/login` here, which is what this used to do, minted one
 * per confirmation and made the account's device list unreadable.
 */
export const useReauthStore = create<ReauthState>((set) => ({
    open: false,
    request: () => set({ open: true }),
    close: () => set({ open: false }),
}))
