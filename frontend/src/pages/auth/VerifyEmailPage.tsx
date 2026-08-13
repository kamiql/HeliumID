import { Box, Button, Divider, Stack, TextField, Typography } from "@mui/material"
import CheckCircleOutlinedIcon from "@mui/icons-material/CheckCircleOutlined"
import { useEffect, useRef, useState } from "react"
import { Link, useSearchParams } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import EmailField from "../../components/EmailField.tsx"
import { LoadingState } from "../../components/ui/StateView.tsx"
import { authApi } from "../../api/auth.ts"
import { notify } from "../../stores/notice.store.ts"
import { MONO_FONT } from "../../lib/theme.ts"

type Phase = "verifying" | "done" | "failed" | "manual"

/**
 * Handles the link mailed at registration: `/verify-email?token=...`.
 *
 * The token is single use and short lived. Verifying does not sign the user in — controlling
 * the mailbox proves the address, not the identity behind it.
 */
export default function VerifyEmailPage() {
    const [searchParams] = useSearchParams()
    const token = searchParams.get("token")

    const [phase, setPhase] = useState<Phase>(token ? "verifying" : "manual")
    const [error, setError] = useState<unknown>(null)
    const [email, setEmail] = useState("")
    const [code, setCode] = useState("")
    const attempted = useRef(false)

    const verify = (candidate: string) => {
        setPhase("verifying")
        authApi
            .verifyEmail(candidate)
            .then(() => setPhase("done"))
            .catch((caught: unknown) => {
                setError(caught)
                setPhase("failed")
            })
    }

    useEffect(() => {
        if (!token || attempted.current) return
        attempted.current = true

        authApi
            .verifyEmail(token)
            .then(() => setPhase("done"))
            .catch((caught: unknown) => {
                setError(caught)
                setPhase("failed")
            })
    }, [token])

    const handleResend = async () => {
        if (!email) return
        try {
            setError(null)
            await authApi.resendVerification(email)
            // Same answer whether or not the address exists.
            notify("If that address needs verification, we have sent a new link.", "success")
        } catch (caught) {
            setError(caught)
        }
    }

    const done = phase === "done"

    return (
        <AuthCard
            title={done ? "Email verified" : "Verify email"}
            statusIcon={done ? <CheckCircleOutlinedIcon /> : undefined}
            statusTone="success"
            subtitle={
                phase === "manual"
                    ? "Paste the code from your email, or request a new link."
                    : undefined
            }
        >
            {phase === "verifying" && <LoadingState label="Confirming your email address…" />}

            {done && (
                <Stack spacing={3}>
                    <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                        Your email address is verified. You can sign in now.
                    </Typography>

                    <Button component={Link} to="/login" fullWidth variant="contained">
                        Continue to sign in
                    </Button>
                </Stack>
            )}

            {(phase === "failed" || phase === "manual") && (
                <Stack spacing={2}>
                    {/* Also covers a failed resend, which leaves the phase alone. */}
                    {error !== null && <ErrorAlert error={error} />}

                    {phase === "failed" && (
                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            That link is no longer valid. Request a new one below.
                        </Typography>
                    )}

                    {phase === "manual" && (
                        <Box
                            component="form"
                            onSubmit={(event) => {
                                event.preventDefault()
                                const candidate = code.trim()
                                if (!candidate) return
                                verify(candidate)
                            }}
                        >
                            <Stack spacing={2}>
                                <TextField
                                    fullWidth
                                    autoFocus
                                    label="Verification code"
                                    value={code}
                                    onChange={(event) => {
                                        setCode(event.target.value)
                                        setError(null)
                                    }}
                                    slotProps={{
                                        input: { sx: { fontFamily: MONO_FONT } },
                                    }}
                                />

                                <Button
                                    type="submit"
                                    fullWidth
                                    variant="contained"
                                    disabled={code.trim().length === 0}
                                >
                                    Verify email
                                </Button>
                            </Stack>
                        </Box>
                    )}

                    {phase === "manual" && (
                        <Divider sx={{ my: 1 }}>
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                or
                            </Typography>
                        </Divider>
                    )}

                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                        Nothing in your inbox? Check your spam folder, then send yourself a fresh
                        link.
                    </Typography>

                    <EmailField
                        fullWidth
                        label="Email address"
                        value={email}
                        onType={(value) => {
                            setEmail(value)
                            setError(null)
                        }}
                    />

                    <Button
                        fullWidth
                        variant={phase === "manual" ? "outlined" : "contained"}
                        disabled={!email}
                        onClick={() => void handleResend()}
                    >
                        Resend verification email
                    </Button>

                    <Button component={Link} to="/login" fullWidth variant="text">
                        Back to sign in
                    </Button>
                </Stack>
            )}
        </AuthCard>
    )
}
