import { Button, CircularProgress, Stack, TextField, Typography } from "@mui/material"
import MarkEmailReadOutlinedIcon from "@mui/icons-material/MarkEmailReadOutlined"
import { useEffect, useRef, useState } from "react"
import { Link, useSearchParams } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import EmailField from "../../components/EmailField.tsx"
import { authApi } from "../../api/auth.ts"
import { notify } from "../../stores/notice.store.ts"

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
    const attempted = useRef(false)

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

    return (
        <AuthCard
            icon={<MarkEmailReadOutlinedIcon />}
            title="Verify email"
            iconColor={phase === "done" ? "success.main" : "primary.main"}
        >
            <Stack spacing={2}>
                {phase === "verifying" && (
                    <Stack spacing={2} sx={{ alignItems: "center" }}>
                        <CircularProgress />
                        <Typography sx={{ color: "text.secondary" }}>
                            Confirming your email address…
                        </Typography>
                    </Stack>
                )}

                {phase === "done" && (
                    <>
                        <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                            Your email address is verified. You can sign in now.
                        </Typography>

                        <Button component={Link} to="/login" fullWidth variant="contained">
                            Continue to sign in
                        </Button>
                    </>
                )}

                {(phase === "failed" || phase === "manual") && (
                    <>
                        {phase === "failed" && <ErrorAlert error={error} />}

                        <Typography sx={{ color: "text.secondary" }}>
                            {phase === "failed"
                                ? "That link is no longer valid. Request a new one below."
                                : "Paste the code from your email, or request a new link."}
                        </Typography>

                        {phase === "manual" && (
                            <TextField
                                fullWidth
                                label="Verification code"
                                onKeyDown={(event) => {
                                    if (event.key !== "Enter") return
                                    const value = (event.target as HTMLInputElement).value.trim()
                                    if (!value) return
                                    setPhase("verifying")
                                    authApi
                                        .verifyEmail(value)
                                        .then(() => setPhase("done"))
                                        .catch((caught: unknown) => {
                                            setError(caught)
                                            setPhase("failed")
                                        })
                                }}
                                helperText="Press Enter to submit"
                            />
                        )}

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
                            variant="contained"
                            disabled={!email}
                            onClick={() => void handleResend()}
                        >
                            Resend verification email
                        </Button>

                        <Button component={Link} to="/login" fullWidth variant="text">
                            Back to sign in
                        </Button>
                    </>
                )}
            </Stack>
        </AuthCard>
    )
}
