import { useEffect, useRef, type ReactNode } from "react"
import { Alert, Box, CircularProgress, Snackbar } from "@mui/material"
import { useAuthStore } from "../stores/auth.store.ts"
import { useNoticeStore } from "../stores/notice.store.ts"
import { useReauthStore } from "../stores/reauth.store.ts"
import { registerApiHandlers } from "../api/axios.ts"
import ReauthDialog from "../components/ReauthDialog.tsx"

/**
 * The interceptor cannot import the stores (that would be circular), so the global reactions
 * from concept §5.6 are wired in here — at module scope, before anything can render or fetch.
 */
registerApiHandlers({
    onSessionLost: () => {
        // Clearing the user is enough: RequireAuth re-renders and redirects to /login.
        useAuthStore.getState().clearSession()
    },
    onEmailUnverified: () => {
        useNoticeStore.getState().push("Verify your email address to complete that action.", "warning")
    },
    onReauthenticationRequired: () => {
        // Freshness only moves when the user signs in again, so this opens a full step-up
        // prompt rather than a cosmetic password box.
        useReauthStore.getState().request()
    },
})

/**
 * Boots the session before anything renders.
 *
 * `GET /v1/auth/session` does double duty: it tells us who is signed in *and* hands out the
 * CSRF token every state-changing request must echo. Nothing may issue a write before it has
 * completed, which is why the tree is held back until then.
 */
export default function AuthProvider({ children }: { children: ReactNode }) {
    const initialized = useAuthStore((state) => state.initialized)
    const bootstrap = useAuthStore((state) => state.bootstrap)
    const notices = useNoticeStore((state) => state.notices)
    const dismiss = useNoticeStore((state) => state.dismiss)
    const started = useRef(false)

    useEffect(() => {
        if (started.current) return
        started.current = true
        void bootstrap()
    }, [bootstrap])

    const current = notices[0]

    return (
        <>
            {initialized ? (
                children
            ) : (
                <Box
                    sx={{
                        minHeight: "100vh",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                    }}
                >
                    <CircularProgress color="primary" />
                </Box>
            )}

            <ReauthDialog />

            <Snackbar
                open={current !== undefined}
                autoHideDuration={6000}
                onClose={() => current && dismiss(current.id)}
                anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
            >
                <Alert
                    severity={current?.severity ?? "info"}
                    variant="filled"
                    onClose={() => current && dismiss(current.id)}
                    sx={{ borderRadius: 2 }}
                >
                    {current?.message}
                </Alert>
            </Snackbar>
        </>
    )
}
