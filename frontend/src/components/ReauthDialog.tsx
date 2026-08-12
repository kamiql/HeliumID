import {
    Alert,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    Typography,
} from "@mui/material"
import { useState } from "react"
import PasswordField from "./PasswordField.tsx"
import ErrorAlert from "./ErrorAlert.tsx"
import MFADialog from "./MFADialog.tsx"
import { useAuthStore, type MfaChallenge } from "../stores/auth.store.ts"
import { useReauthStore } from "../stores/reauth.store.ts"
import { notify } from "../stores/notice.store.ts"
import type { MfaMethod } from "../api/types.ts"

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
    const [error, setError] = useState<unknown>(null)
    const [busy, setBusy] = useState(false)

    if (!open || !user) return null

    const finish = () => {
        setPassword("")
        setChallenge(null)
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

    const handleMfa = async (method: MfaMethod, code: string) => {
        await completeMfa(challenge!.transactionId, method, code)
        finish()
    }

    return (
        <>
            <Dialog
                open={challenge === null}
                onClose={() => (busy ? undefined : close())}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Confirm your identity</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <Alert severity="info">
                            This action needs a recent sign-in. Enter your password to continue.
                        </Alert>

                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Signed in as <strong>{user.username}</strong>.
                        </Typography>

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
                    >
                        Confirm
                    </Button>
                </DialogActions>
            </Dialog>

            <MFADialog
                challenge={challenge}
                onSubmit={handleMfa}
                onCancel={() => {
                    setChallenge(null)
                    close()
                }}
            />
        </>
    )
}
