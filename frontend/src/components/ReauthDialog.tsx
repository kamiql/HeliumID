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
import { authApi } from "../api/auth.ts"
import { readMfaChallenge, useAuthStore, type MfaChallenge } from "../stores/auth.store.ts"
import { useReauthStore } from "../stores/reauth.store.ts"
import { notify } from "../stores/notice.store.ts"
import { toHeliumError } from "../api/problem.ts"
import type { MfaSecondFactor, MfaVerifyRequest } from "../api/types.ts"

/**
 * Step-up prompt for operations that demand recent proof of identity.
 *
 * Sensitive operations (password and email changes, MFA management, every admin write) require
 * the session to have authenticated within a short window, and this is what refreshes it —
 * password first, second factor after, exactly as at sign-in, because a bare password check
 * would be a weaker bar than the sign-in it is standing in for.
 *
 * What it does **not** do is sign in again. It used to: `POST /v1/auth/login` was the only thing
 * that moved the freshness clock, so every confirmed deletion, password change and MFA edit
 * minted another session, and the account's device list — whose entire job is to let somebody
 * spot the session that should not be there — filled up with entries from this browser that the
 * user had no way to recognise. `/v1/auth/reauthenticate` refreshes the session already in hand.
 */
export default function ReauthDialog() {
    const open = useReauthStore((state) => state.open)
    const close = useReauthStore((state) => state.close)
    const user = useAuthStore((state) => state.user)

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

            await authApi.reauthenticate(password)
            setPassword("")
            finish()
        } catch (caught) {
            setPassword("")

            // `mfa_required` is the ordinary second half of a step-up, not a failure: the
            // password bought a one-time handle and the factor is presented against that, so the
            // password never has to be held across the challenge.
            const pending = readMfaChallenge(caught)
            if (pending) {
                setChallenge(pending)
                return
            }

            setError(caught)
        } finally {
            setBusy(false)
        }
    }

    const handleMfa = async (factor: MfaSecondFactor) => {
        const transactionId = challenge!.transactionId
        // Built per method rather than spread from one object: the endpoint accepts exactly one
        // of `code` and `webauthn`, and sending the other as `undefined` is not the same thing.
        // No `remember_device` in either shape — trusting a device lowers the bar for future
        // sign-ins, which is not a thing to grant from a confirmation prompt.
        const request: MfaVerifyRequest =
            factor.method === "webauthn"
                ? { transaction_id: transactionId, method: factor.method, webauthn: factor.assertion }
                : { transaction_id: transactionId, method: factor.method, code: factor.code }

        try {
            await authApi.completeReauthMfa(request)
        } catch (caught) {
            // Rethrown for MFADialog, which distinguishes an expired handle and a dismissed
            // passkey prompt from a wrong code and reacts to each differently.
            throw toHeliumError(caught)
        }
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
