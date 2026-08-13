import {
    Box,
    Button,
    CircularProgress,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    Stack,
} from "@mui/material"
import { useId, useState } from "react"
import PasswordField from "./PasswordField.tsx"
import ErrorAlert from "./ErrorAlert.tsx"
import MFADialog from "./MFADialog.tsx"
import { useAuthStore, type MfaChallenge } from "../stores/auth.store.ts"
import { useReauthStore } from "../stores/reauth.store.ts"
import { notify } from "../stores/notice.store.ts"
import type { MfaSecondFactor } from "../api/types.ts"

/**
 * Step-up prompt for operations that demand recent proof of identity.
 *
 * Sensitive operations (password and email changes, MFA management, every admin write) require
 * the session to have authenticated within a short window. Re-running the full sign-in — second
 * factor included — is what refreshes that window; a bare password check would be a weaker
 * bar than the original sign-in.
 */
export default function ReauthDialog() {
    const open = useReauthStore((state) => state.open)
    const close = useReauthStore((state) => state.close)
    const user = useAuthStore((state) => state.user)
    const login = useAuthStore((state) => state.login)
    const completeMfa = useAuthStore((state) => state.completeMfa)

    const [password, setPassword] = useState("")
    const [challenge, setChallenge] = useState<MfaChallenge | null>(null)
    /**
     * The second factor is a separate dialog, so it is held back until the password dialog has
     * finished animating out. Two stacked modals on screen at once read as a glitch rather than
     * as the second step of one flow.
     */
    const [challengeVisible, setChallengeVisible] = useState(false)
    const [error, setError] = useState<unknown>(null)
    const [busy, setBusy] = useState(false)

    const titleId = useId()
    const descriptionId = useId()

    if (!open || !user) return null

    const finish = () => {
        setPassword("")
        setChallenge(null)
        setChallengeVisible(false)
        setError(null)
        close()
        notify("Identity confirmed. Please retry what you were doing.", "success")
    }

    const handleSubmit = async () => {
        if (!password || busy) return

        try {
            setBusy(true)
            setError(null)

            const pending = await login({ identifier: user.username, password })
            setPassword("")

            if (pending) {
                setChallenge(pending)
                return
            }

            finish()
        } catch (caught) {
            setError(caught)
        } finally {
            setBusy(false)
        }
    }

    const handleMfa = async (factor: MfaSecondFactor) => {
        await completeMfa(challenge!.transactionId, factor)
        finish()
    }

    return (
        <>
            <Dialog
                open={challenge === null}
                onClose={() => (busy ? undefined : close())}
                fullWidth
                maxWidth="xs"
                aria-labelledby={titleId}
                aria-describedby={descriptionId}
                slotProps={{
                    transition: {
                        // Hand-off point: the code prompt only appears once this one is gone.
                        onExited: () => setChallengeVisible(challenge !== null),
                    },
                }}
            >
                <DialogTitle id={titleId}>Confirm your identity</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <DialogContentText id={descriptionId} variant="body2">
                            This change needs a recent sign-in. Enter the password for{" "}
                            <Box component="strong" sx={{ color: "text.primary", fontWeight: 600 }}>
                                {user.username}
                            </Box>{" "}
                            to continue. If your account uses two-factor authentication, you will
                            be asked for a code next.
                        </DialogContentText>

                        <PasswordField
                            fullWidth
                            autoFocus
                            label="Password"
                            autoComplete="current-password"
                            value={password}
                            onType={(value) => {
                                setPassword(value)
                                setError(null)
                            }}
                        />

                        {error !== null && <ErrorAlert error={error} />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <Button onClick={close} disabled={busy}>
                        Cancel
                    </Button>

                    <Button
                        variant="contained"
                        onClick={() => void handleSubmit()}
                        disabled={busy || !password}
                        startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined}
                    >
                        Confirm
                    </Button>
                </DialogActions>
            </Dialog>

            <MFADialog
                challenge={challengeVisible ? challenge : null}
                onSubmit={handleMfa}
                onCancel={() => {
                    setChallenge(null)
                    setChallengeVisible(false)
                    close()
                }}
            />
        </>
    )
}
