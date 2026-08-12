import { create } from "zustand"

type ReauthState = {
    open: boolean
    /** Opened by the axios interceptor when the server answers `reauthentication_required`. */
    request: () => void
    close: () => void
}

/**
 * There is no dedicated "re-authenticate" endpoint: freshness is measured from the session's
 * `authenticatedAt`, and the only thing that moves it is signing in again. The dialog therefore
 * replays `POST /v1/auth/login` — including its MFA challenge — rather than inventing a
 * weaker password-confirmation route.
 */
export const useReauthStore = create<ReauthState>((set) => ({
    open: false,
    request: () => set({ open: true }),
    close: () => set({ open: false }),
}))
