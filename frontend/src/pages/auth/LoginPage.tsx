import { Box, Button, Divider, Link as MuiLink, Stack, TextField, Typography } from "@mui/material"
import { useState } from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import PasswordField from "../../components/PasswordField.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import MFADialog from "../../components/MFADialog.tsx"
import ProviderButtons from "../../components/ProviderButtons.tsx"
import { useAuth } from "../../hooks/useAuth.ts"
import { authApi } from "../../api/auth.ts"
import { ErrorCode, toHeliumError } from "../../api/problem.ts"
import { notify } from "../../stores/notice.store.ts"
import type { MfaChallenge } from "../../stores/auth.store.ts"
import type { MfaSecondFactor } from "../../api/types.ts"

export default function LoginPage() {
    const { login, completeMfa, loading } = useAuth()
    const navigate = useNavigate()
    const [searchParams] = useSearchParams()

    const [identifier, setIdentifier] = useState("")
    const [password, setPassword] = useState("")
    const [error, setError] = useState<unknown>(null)
    const [challenge, setChallenge] = useState<MfaChallenge | null>(null)
    const [needsVerification, setNeedsVerification] = useState(false)

    const returnTo = searchParams.get("return_to")

    const finish = () => {
        // Only same-origin relative paths are honoured: taking an absolute URL from the query
        // string would turn this page into an open redirector.
        const safe = returnTo && returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/"
        navigate(safe, { replace: true })
    }

    const handleLogin = async () => {
        if (!identifier || !password) {
            setError(new Error("missing"))
            return
        }

        try {
            setError(null)
            setNeedsVerification(false)

            const pending = await login({ identifier, password })

            if (pending) {
                // Phase two. The password is dropped here — only the transaction handle matters.
                setPassword("")
                setChallenge(pending)
                return
            }

            finish()
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            if (heliumError.is(ErrorCode.EMAIL_UNVERIFIED)) {
                setNeedsVerification(true)
            }
            setError(heliumError)
        }
    }

    const handleMfa = async (factor: MfaSecondFactor, rememberDevice: boolean) => {
        await completeMfa(challenge!.transactionId, factor, rememberDevice)
        setChallenge(null)
        finish()
    }

    const handleResend = async () => {
        try {
            await authApi.resendVerification(identifier)
            notify("If that address needs verification, we have sent a new link.", "success")
        } catch (caught) {
            setError(caught)
        }
    }

    // The submit guard rejects the form before it reaches the network, so an error raised while
    // a field is empty is the local one — it belongs on that field, not in a banner.
    const blockedLocally = error !== null && (!identifier || !password)

    return (
        <>
            <AuthCard
                title="Sign in"
                subtitle="Use your HeliumID account to continue."
                footer={
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                        Don&apos;t have an account?{" "}
                        <MuiLink component={Link} to="/register">
                            Sign up
                        </MuiLink>
                    </Typography>
                }
            >
                <Box
                    component="form"
                    onSubmit={(event) => {
                        event.preventDefault()
                        void handleLogin()
                    }}
                >
                    <Stack spacing={2}>
                        <TextField
                            required
                            fullWidth
                            label="Username or email"
                            autoComplete="username"
                            autoFocus
                            value={identifier}
                            onChange={(event) => {
                                setIdentifier(event.target.value)
                                setError(null)
                            }}
                            error={blockedLocally && !identifier}
                            helperText={
                                blockedLocally && !identifier
                                    ? "Enter your username or email address."
                                    : undefined
                            }
                        />

                        <PasswordField
                            required
                            fullWidth
                            label="Password"
                            autoComplete="current-password"
                            value={password}
                            onType={(value) => {
                                setPassword(value)
                                setError(null)
                            }}
                            error={blockedLocally && !password}
                            helperText={
                                blockedLocally && !password ? "Enter your password." : undefined
                            }
                        />

                        {error !== null && !blockedLocally && (
                            <ErrorAlert
                                error={error}
                                // The remedy belongs with the problem, not further down the form.
                                action={
                                    needsVerification ? (
                                        <Button
                                            color="inherit"
                                            size="small"
                                            onClick={() => void handleResend()}
                                        >
                                            Resend verification email
                                        </Button>
                                    ) : undefined
                                }
                            />
                        )}

                        <Button type="submit" fullWidth variant="contained" disabled={loading}>
                            Sign in
                        </Button>

                        <Box sx={{ display: "flex", justifyContent: "center" }}>
                            <MuiLink component={Link} to="/forgot-password" variant="body2">
                                Forgot password?
                            </MuiLink>
                        </Box>
                    </Stack>

                    <Divider sx={{ my: 3 }}>
                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                            or
                        </Typography>
                    </Divider>

                    <ProviderButtons />
                </Box>
            </AuthCard>

            <MFADialog
                challenge={challenge}
                allowRememberDevice
                onSubmit={handleMfa}
                onCancel={() => {
                    setChallenge(null)
                    notify("Verification cancelled. Please sign in again.", "info")
                }}
            />
        </>
    )
}
