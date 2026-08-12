import {
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    TextField,
    Typography,
} from "@mui/material"
import { useState } from "react"
import OtpInput from "./OtpInput.tsx"
import { describeError, ErrorCode, toHeliumError } from "../api/problem.ts"
import type { MfaMethod } from "../api/types.ts"
import type { MfaChallenge } from "../stores/auth.store.ts"

type MFADialogProps = {
    challenge: MfaChallenge | null
    /** Submits the second factor against the one-time transaction handle. */
    onSubmit: (method: MfaMethod, code: string) => Promise<void>
    /** Called when the transaction expired or the user gave up — restart from the password. */
    onCancel: () => void
}

const METHOD_LABELS: Record<MfaMethod, string> = {
    totp: "Authenticator app",
    recovery_code: "Recovery code",
    webauthn: "Security key",
}

/**
 * Phase two of login.
 *
 * The dialog never sees the password. It holds only the `transaction_id` the server issued
 * with the `mfa_required` problem, which is single-use and short-lived: if it expires the user
 * has to start again from the password rather than retry indefinitely.
 */
export default function MFADialog({ challenge, onSubmit, onCancel }: MFADialogProps) {
    if (!challenge) return null

    // Keyed on the transaction so a new challenge gets a clean dialog instead of state that
    // has to be reset in an effect.
    return (
        <MfaChallengeDialog
            key={challenge.transactionId}
            challenge={challenge}
            onSubmit={onSubmit}
            onCancel={onCancel}
        />
    )
}

function MfaChallengeDialog({
    challenge,
    onSubmit,
    onCancel,
}: MFADialogProps & { challenge: MfaChallenge }) {
    const [method, setMethod] = useState<MfaMethod>(() =>
        challenge.methods.includes("totp") ? "totp" : challenge.methods[0],
    )
    const [code, setCode] = useState("")
    const [recoveryCode, setRecoveryCode] = useState("")
    const [error, setError] = useState("")
    const [submitting, setSubmitting] = useState(false)

    const value = method === "totp" ? code : recoveryCode
    const canSubmit = method === "totp" ? code.length === 6 : recoveryCode.trim().length > 0

    const handleSubmit = async (candidate = value) => {
        if (submitting) return
        if (method === "totp" ? candidate.length !== 6 : candidate.trim().length === 0) return

        try {
            setSubmitting(true)
            setError("")
            await onSubmit(method, candidate.trim())
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            setCode("")
            setRecoveryCode("")

            if (heliumError.is(ErrorCode.MFA_EXPIRED)) {
                // The handle is spent. Anything the user types now would be rejected, so send
                // them back to the password step rather than leave a dead dialog open.
                setError("")
                onCancel()
                return
            }
            setError(describeError(heliumError))
        } finally {
            setSubmitting(false)
        }
    }

    return (
        <Dialog open fullWidth maxWidth="xs" onClose={() => (submitting ? undefined : onCancel())}>
            <DialogTitle>Additional verification required</DialogTitle>

            <DialogContent>
                <Stack spacing={2}>
                    {challenge.methods.length > 1 && (
                        <Stack direction="row" spacing={1}>
                            {challenge.methods.map((candidate) => (
                                <Button
                                    key={candidate}
                                    fullWidth
                                    size="small"
                                    variant={candidate === method ? "contained" : "outlined"}
                                    onClick={() => {
                                        setMethod(candidate)
                                        setError("")
                                    }}
                                >
                                    {METHOD_LABELS[candidate]}
                                </Button>
                            ))}
                        </Stack>
                    )}

                    {method === "totp" && (
                        <>
                            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                Enter the 6-digit code from your authenticator app.
                            </Typography>

                            <OtpInput
                                value={code}
                                onChange={(next) => {
                                    setCode(next)
                                    setError("")
                                    if (next.length === 6) void handleSubmit(next)
                                }}
                                autoFocus
                            />
                        </>
                    )}

                    {method === "recovery_code" && (
                        <>
                            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                Enter one of the recovery codes you saved when you enabled
                                two-factor authentication. Each code works only once.
                            </Typography>

                            <TextField
                                fullWidth
                                autoFocus
                                label="Recovery code"
                                autoComplete="one-time-code"
                                value={recoveryCode}
                                onChange={(event) => {
                                    setRecoveryCode(event.target.value)
                                    setError("")
                                }}
                                onKeyDown={(event) => {
                                    if (event.key === "Enter") void handleSubmit()
                                }}
                            />
                        </>
                    )}

                    {method === "webauthn" && (
                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Security keys are not supported by this interface yet. Use your
                            authenticator app or a recovery code.
                        </Typography>
                    )}

                    {error && (
                        <Typography color="error" variant="body2">
                            {error}
                        </Typography>
                    )}
                </Stack>
            </DialogContent>

            <DialogActions>
                <Button onClick={onCancel} disabled={submitting}>
                    Cancel
                </Button>

                <Button
                    variant="contained"
                    onClick={() => void handleSubmit()}
                    disabled={submitting || !canSubmit || method === "webauthn"}
                >
                    Verify
                </Button>
            </DialogActions>
        </Dialog>
    )
}
