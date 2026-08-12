import {
    Avatar,
    Box,
    Button,
    Container,
    Divider,
    Link as MuiLink,
    Paper,
    TextField,
    Typography,
} from "@mui/material"
import LockOutlinedIcon from "@mui/icons-material/LockOutlined"
import { useState } from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import PasswordField from "../../components/PasswordField.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import MFADialog from "../../components/MFADialog.tsx"
import ProviderButtons from "../../components/ProviderButtons.tsx"
import { useAuth } from "../../hooks/useAuth.ts"
import { authApi } from "../../api/auth.ts"
import { ErrorCode, toHeliumError } from "../../api/problem.ts"
import { notify } from "../../stores/notice.store.ts"
import type { MfaChallenge } from "../../stores/auth.store.ts"
import type { MfaMethod } from "../../api/types.ts"

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

    const handleMfa = async (method: MfaMethod, code: string) => {
        await completeMfa(challenge!.transactionId, method, code)
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

    return (
        <>
            <Container component="main" maxWidth="xs">
                <Paper
                    elevation={8}
                    sx={{
                        p: 4,
                        width: "100%",
                        borderRadius: 3,
                        backgroundColor: "background.paper",
                    }}
                >
                    <Box
                        sx={{
                            display: "flex",
                            flexDirection: "column",
                            alignItems: "center",
                        }}
                    >
                        <Avatar
                            sx={{
                                mb: 2,
                                bgcolor: "primary.main",
                            }}
                        >
                            <LockOutlinedIcon />
                        </Avatar>

                        <Typography
                            component="h1"
                            variant="h4"
                            sx={{
                                fontFamily: "Silkscreen",
                                mb: 3,
                            }}
                        >
                            Sign in
                        </Typography>

                        <Box
                            component="form"
                            sx={{ width: "100%" }}
                            onSubmit={(event) => {
                                event.preventDefault()
                                void handleLogin()
                            }}
                        >
                            <TextField
                                margin="normal"
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
                                error={Boolean(error) && !identifier}
                            />

                            <PasswordField
                                margin="normal"
                                required
                                fullWidth
                                label="Password"
                                autoComplete="current-password"
                                value={password}
                                onType={(value) => {
                                    setPassword(value)
                                    setError(null)
                                }}
                                error={Boolean(error) && !password}
                            />

                            {error !== null && (identifier && password ? (
                                <Box sx={{ mt: 2 }}>
                                    <ErrorAlert error={error} />
                                </Box>
                            ) : (
                                <Typography color="error" variant="body2" sx={{ mt: 1 }}>
                                    Please fill out all fields
                                </Typography>
                            ))}

                            {needsVerification && (
                                <Button
                                    fullWidth
                                    variant="text"
                                    sx={{ mt: 1 }}
                                    onClick={() => void handleResend()}
                                >
                                    Resend verification email
                                </Button>
                            )}

                            <Button
                                type="submit"
                                fullWidth
                                variant="contained"
                                disabled={loading}
                                sx={{
                                    mt: 2,
                                    mb: 2,
                                    py: 1.2,
                                }}
                            >
                                Sign in
                            </Button>

                            <Box
                                sx={{
                                    display: "flex",
                                    justifyContent: "center",
                                }}
                            >
                                <MuiLink component={Link} to="/forgot-password" variant="body2">
                                    Forgot password?
                                </MuiLink>
                            </Box>

                            <Divider sx={{ my: 2 }}>or</Divider>

                            <Box
                                sx={{
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: 2,
                                }}
                            >
                                <ProviderButtons />

                                <Typography sx={{ textAlign: "center" }}>
                                    Don&apos;t have an account?{" "}
                                    <MuiLink component={Link} to="/register" variant="body2">
                                        Sign up
                                    </MuiLink>
                                </Typography>
                            </Box>
                        </Box>
                    </Box>
                </Paper>
            </Container>

            <MFADialog
                challenge={challenge}
                onSubmit={handleMfa}
                onCancel={() => {
                    setChallenge(null)
                    notify("Verification cancelled. Please sign in again.", "info")
                }}
            />
        </>
    )
}
