import {
    Avatar,
    Box,
    Button,
    Container,
    Divider,
    Link,
    Paper,
    Typography,
} from "@mui/material"
import LockOutlinedIcon from "@mui/icons-material/LockOutlined"
import { useState } from "react"
import EmailField from "../../components/EmailField.tsx"
import PasswordField from "../../components/PasswordField.tsx"
import { DiscordIcon, GoogleIcon } from "../../components/global/Icons.tsx"
import { useAuth } from "../../hooks/useAuth.ts"
import { authApi } from "../../api/auth.ts"
import { useSearchParams } from "react-router"
import MFADialog from "../../components/MFADialog.tsx"
import VerificationDialog from "../../components/VerificationDialog.tsx"
import type { RequireMFAResponse } from "../../stores/auth.store.ts"

export default function LoginPage() {
    const {
        login,
        completeLogin,
        loading,
    } = useAuth()

    const [searchParams] = useSearchParams()
    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")
    const [error, setError] = useState(searchParams.get("error"))

    const [mfa, setMfa] = useState<RequireMFAResponse | null>(null)
    const [verificationId, setVerificationId] = useState<string | null>(null)

    const handleLogin = async () => {
        if (!email || !password) {
            setError("Please fill out all fields")
            return
        }

        try {
            setError("")

            const res = await login({
                email,
                password,
            })

            if (res) {
                setMfa(res)
            }
        } catch {
            setError("Invalid credentials")
        }
    }

    const handleMFA = async (type: string) => {
        if (!mfa) {
            return
        }

        try {
            const response = await authApi.mfa({
                userId: mfa.userId,
                type,
            })

            setMfa(null)
            setVerificationId(response.data)
        } catch {
            setError("Failed to start verification")
        }
    }

    const handleVerificationCompleted = async () => {
        setVerificationId(null)
        await completeLogin()
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

                        <Box component="form" sx={{ width: "100%" }}>
                            <EmailField
                                margin="normal"
                                required
                                fullWidth
                                label="Email"
                                autoComplete="email"
                                autoFocus
                                value={email}
                                onType={(value) => {
                                    setEmail(value)
                                    setError("")
                                }}
                                error={!!error && !email}
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
                                    setError("")
                                }}
                                error={!!error && !password}
                            />

                            {error && (
                                <Typography
                                    color="error"
                                    variant="body2"
                                    sx={{ mt: 1 }}
                                >
                                    {error}
                                </Typography>
                            )}

                            <Button
                                fullWidth
                                variant="contained"
                                disabled={loading}
                                onClick={handleLogin}
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
                                <Link href="#" variant="body2">
                                    Forgot password?
                                </Link>
                            </Box>

                            <Divider sx={{ my: 2 }}>
                                or
                            </Divider>

                            <Box
                                sx={{
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: 2,
                                }}
                            >
                                <Button
                                    fullWidth
                                    variant="outlined"
                                    startIcon={<GoogleIcon />}
                                    onClick={() => {
                                        authApi.oauth("google")
                                    }}
                                >
                                    Sign in with Google
                                </Button>

                                <Button
                                    fullWidth
                                    variant="outlined"
                                    startIcon={<DiscordIcon />}
                                    onClick={() => {
                                        authApi.oauth("discord")
                                    }}
                                >
                                    Sign in with Discord
                                </Button>

                                <Typography sx={{ textAlign: "center" }}>
                                    Don&apos;t have an account?{" "}
                                    <Link
                                        href="/register"
                                        variant="body2"
                                    >
                                        Sign up
                                    </Link>
                                </Typography>
                            </Box>
                        </Box>
                    </Box>
                </Paper>
            </Container>

            <MFADialog
                open={mfa !== null}
                types={mfa?.types ?? []}
                onSelect={handleMFA}
            />

            <VerificationDialog
                open={verificationId !== null}
                verificationId={verificationId}
                onClose={() => setVerificationId(null)}
                onCompleted={handleVerificationCompleted}
            />
        </>
    )
}