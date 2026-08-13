import { useEffect, useRef, type ReactNode } from "react"
import { Alert, Box, CircularProgress, Snackbar, Stack, Typography, useMediaQuery } from "@mui/material"
import type { Theme } from "@mui/material/styles"
import { useAuthStore } from "../stores/auth.store.ts"
import { useNoticeStore } from "../stores/notice.store.ts"
import { useReauthStore } from "../stores/reauth.store.ts"
import { registerApiHandlers } from "../api/axios.ts"
import ReauthDialog from "../components/ReauthDialog.tsx"
import Brand from "../components/global/Brand.tsx"

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
    const compact = useMediaQuery((theme: Theme) => theme.breakpoints.down("sm"))

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
                    role="status"
                    aria-live="polite"
                    sx={{
                        minHeight: "100vh",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        p: 3,
                    }}
                >
                    {/* Not a link: this renders outside the router, so Brand must stay inert. */}
                    <Stack spacing={2.5} sx={{ alignItems: "center", textAlign: "center" }}>
                        <Brand />

                        <CircularProgress color="primary" size={26} />

                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Restoring your session…
                        </Typography>
                    </Stack>
                </Box>
            )}

            <ReauthDialog />

            {/*
              * Mounted only while a notice is queued, and keyed on its id, so the next message
              * replaces the current one immediately. Without the key MUI keeps the open
              * snackbar on screen and the queue looks stuck behind whatever is showing.
              */}
            {current && (
                <Snackbar
                    key={current.id}
                    open
                    autoHideDuration={6000}
                    onClose={(_event, reason) => {
                        // A click anywhere should not wipe a message the user has not read yet.
                        if (reason === "clickaway") return
                        dismiss(current.id)
                    }}
                    anchorOrigin={{
                        vertical: "bottom",
                        horizontal: compact ? "center" : "right",
                    }}
                    // Below sm the snackbar already spans the viewport, so only the desktop
                    // side needs a cap — long messages then wrap instead of stretching across
                    // the page.
                    sx={{ maxWidth: { sm: 440 } }}
                >
                    <Alert
                        severity={current.severity}
                        variant="filled"
                        // Failures interrupt; confirmations do not.
                        role={current.severity === "error" ? "alert" : "status"}
                        onClose={() => dismiss(current.id)}
                        sx={{
                            borderRadius: 2,
                            width: "100%",
                            alignItems: "center",
                            // Long sentences wrap instead of being clipped on a narrow screen.
                            "& .MuiAlert-message": { overflowWrap: "anywhere" },
                        }}
                    >
                        {current.message}
                    </Alert>
                </Snackbar>
            )}
        </>
    )
}
