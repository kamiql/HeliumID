import {
    Alert,
    Box,
    Button,
    Checkbox,
    CircularProgress,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    FormControlLabel,
    Stack,
    TextField,
    ToggleButton,
    ToggleButtonGroup,
    Typography,
} from "@mui/material"
import { Fingerprint, PhoneIphone, VpnKey } from "@mui/icons-material"
import { useId, useState, type ReactElement } from "react"
import OtpInput from "./OtpInput.tsx"
import { authApi } from "../api/auth.ts"
import { describeError, ErrorCode, HeliumError, toHeliumError } from "../api/problem.ts"
import { getWebauthnAssertion, webauthnUnavailable } from "../lib/webauthn.ts"
import type { MfaMethod, MfaSecondFactor } from "../api/types.ts"
import type { MfaChallenge } from "../stores/auth.store.ts"

type MFADialogProps = {
    challenge: MfaChallenge | null
    /**
     * Offers "trust this device". Opt-in per call site: skipping the second factor next time is
     * a sign-in decision, and a step-up prompt is not the place to lower the bar for later.
     */
    allowRememberDevice?: boolean
    /** Submits the second factor against the one-time transaction handle. */
    onSubmit: (factor: MfaSecondFactor, rememberDevice: boolean) => Promise<void>
    /** Called when the transaction expired or the user gave up — restart from the password. */
    onCancel: () => void
}

const METHOD_LABELS: Record<MfaMethod, string> = {
    totp: "Authenticator app",
    recovery_code: "Recovery code",
    webauthn: "Security key",
}

const METHOD_ICONS: Record<MfaMethod, ReactElement> = {
    totp: <PhoneIphone fontSize="small" />,
    recovery_code: <VpnKey fontSize="small" />,
    webauthn: <Fingerprint fontSize="small" />,
}

/**
 * Phase two of login.
 *
 * The dialog never sees the password. It holds only the `transaction_id` the server issued
 * with the `mfa_required` problem, which is single-use and short-lived: if it expires the user
 * has to start again from the password rather than retry indefinitely.
 */
export default function MFADialog({
    challenge,
    allowRememberDevice = false,
    onSubmit,
    onCancel,
}: MFADialogProps) {
    if (!challenge) return null

    // Keyed on the transaction so a new challenge gets a clean dialog instead of state that
    // has to be reset in an effect.
    return (
        <MfaChallengeDialog
            key={challenge.transactionId}
            challenge={challenge}
            allowRememberDevice={allowRememberDevice}
            onSubmit={onSubmit}
            onCancel={onCancel}
        />
    )
}

function MfaChallengeDialog({
    challenge,
    allowRememberDevice,
    onSubmit,
    onCancel,
}: MFADialogProps & { challenge: MfaChallenge }) {
    const [method, setMethod] = useState<MfaMethod>(() =>
        challenge.methods.includes("totp") ? "totp" : challenge.methods[0],
    )
    const [code, setCode] = useState("")
    const [recoveryCode, setRecoveryCode] = useState("")
    const [rememberDevice, setRememberDevice] = useState(false)
    const [error, setError] = useState("")
    /** A dismissed passkey prompt, kept apart from [error] so it can be said quietly. */
    const [dismissed, setDismissed] = useState(false)
    const [submitting, setSubmitting] = useState(false)

    const titleId = useId()
    const descriptionId = useId()

    const passkeyUnavailable = webauthnUnavailable()
    const value = method === "totp" ? code : recoveryCode
    const canSubmit =
        method === "webauthn"
            ? passkeyUnavailable === null
            : method === "totp"
              ? code.length === 6
              : recoveryCode.trim().length > 0

    /** One place where a second-factor attempt becomes either a signed-in user or a message. */
    const attempt = async (collect: () => Promise<MfaSecondFactor>) => {
        if (submitting) return

        try {
            setSubmitting(true)
            setError("")
            setDismissed(false)
            await onSubmit(await collect(), rememberDevice)
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

            if (heliumError.is(ErrorCode.WEBAUTHN_CANCELLED)) {
                // Closing the browser's prompt is a choice, not a failed sign-in. An alarming
                // red alert here would suggest something broke when nothing did.
                setDismissed(true)
                return
            }

            setError(describeError(heliumError))
        } finally {
            setSubmitting(false)
        }
    }

    const handleSubmit = async (candidate = value) => {
        if (method === "webauthn") return
        if (method === "totp" ? candidate.length !== 6 : candidate.trim().length === 0) return

        await attempt(async () => ({ method, code: candidate.trim() }))
    }

    const handlePasskey = async () => {
        await attempt(async () => {
            // The challenge is drawn per attempt: it is single-use and bound to this
            // transaction, so a retry needs a fresh one rather than a replay of the last.
            const { data } = await authApi.mfaChallenge({
                transaction_id: challenge.transactionId,
                method: "webauthn",
            })

            if (!data.webauthn) {
                throw new HeliumError(null, 0, ErrorCode.WEBAUTHN_FAILED)
            }

            return { method: "webauthn", assertion: await getWebauthnAssertion(data.webauthn) }
        })
    }

    return (
        <Dialog
            open
            fullWidth
            maxWidth="xs"
            aria-labelledby={titleId}
            aria-describedby={descriptionId}
            onClose={() => (submitting ? undefined : onCancel())}
        >
            <DialogTitle id={titleId}>Additional verification required</DialogTitle>

            <DialogContent>
                <Stack spacing={2}>
                    <DialogContentText id={descriptionId} variant="body2">
                        Your account is protected by two-factor authentication. Confirm this
                        sign-in with a second factor to continue.
                    </DialogContentText>

                    {challenge.methods.length > 1 && (
                        <ToggleButtonGroup
                            exclusive
                            fullWidth
                            size="small"
                            value={method}
                            aria-label="Verification method"
                            onChange={(_event, next: MfaMethod | null) => {
                                // `exclusive` reports null when the active button is clicked
                                // again; there is no "no method" state to fall back to.
                                if (next === null) return
                                setMethod(next)
                                setError("")
                                setDismissed(false)
                            }}
                            sx={{
                                "& .MuiToggleButton-root": {
                                    flex: 1,
                                    gap: 0.75,
                                    py: 1,
                                    // Stacked on a narrow screen so three labels never
                                    // squeeze each other out at 360px.
                                    flexDirection: { xs: "column", sm: "row" },
                                    fontSize: "0.75rem",
                                    lineHeight: 1.3,
                                },
                            }}
                        >
                            {challenge.methods.map((candidate) => (
                                <ToggleButton
                                    key={candidate}
                                    value={candidate}
                                    aria-label={METHOD_LABELS[candidate]}
                                >
                                    {METHOD_ICONS[candidate]}
                                    {METHOD_LABELS[candidate]}
                                </ToggleButton>
                            ))}
                        </ToggleButtonGroup>
                    )}

                    {/*
                      * Above the code field, not below it: the OTP input submits itself on the
                      * sixth digit, so anything placed after it is unreachable in the normal
                      * typing flow. Asking before the factor is presented also puts the decision
                      * in the right order — you choose to lower the bar, then clear it.
                      */}
                    {allowRememberDevice && (
                        <Box
                            sx={{
                                p: 1.5,
                                borderRadius: 2,
                                border: "1px solid",
                                borderColor: "divider",
                            }}
                        >
                            <FormControlLabel
                                sx={{ mr: 0 }}
                                control={
                                    <Checkbox
                                        checked={rememberDevice}
                                        onChange={(event) =>
                                            setRememberDevice(event.target.checked)
                                        }
                                    />
                                }
                                label="Trust this device for 30 days"
                            />

                            <Typography variant="caption" component="p" sx={{ color: "text.secondary" }}>
                                We will not ask for a second factor here for the next 30 days.
                                Only do this on a device you control, and revoke it from your
                                account if you lose it.
                            </Typography>
                        </Box>
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
                        <>
                            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                Use the passkey or security key you registered for this account.
                                Your browser will ask you to confirm — the key never leaves your
                                device.
                            </Typography>

                            {passkeyUnavailable !== null && (
                                // Not a failure of the sign-in — an option this browser cannot
                                // offer. Said as information, with the other methods still there.
                                <Alert severity="info">
                                    {describeError(passkeyUnavailable)}{" "}
                                    {challenge.methods.length > 1
                                        ? "Use your authenticator app or a recovery code instead."
                                        : "Sign in from a browser that supports passkeys."}
                                </Alert>
                            )}

                            {dismissed && (
                                <Alert severity="info">
                                    The prompt was dismissed. Choose “Use passkey” when you are
                                    ready to try again.
                                </Alert>
                            )}
                        </>
                    )}

                    {error && (
                        <Alert severity="error" role="alert">
                            {error}
                        </Alert>
                    )}
                </Stack>
            </DialogContent>

            <DialogActions>
                <Button onClick={onCancel} disabled={submitting}>
                    Cancel
                </Button>

                <Button
                    variant="contained"
                    onClick={() =>
                        method === "webauthn" ? void handlePasskey() : void handleSubmit()
                    }
                    disabled={submitting || !canSubmit}
                    startIcon={
                        submitting ? <CircularProgress size={16} color="inherit" /> : undefined
                    }
                >
                    {method === "webauthn" ? "Use passkey" : "Verify"}
                </Button>
            </DialogActions>
        </Dialog>
    )
}
