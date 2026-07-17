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
import {useAuth} from "../../hooks/useAuth.ts";
import {authApi} from "../../api/auth.ts";
import {useSearchParams} from "react-router";

export default function LoginPage() {
    const { login, loading } = useAuth()

    const [searchParams] = useSearchParams()
    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")
    const [error, setError] = useState(searchParams.get("error"))

    const handleLogin = async () => {
        if (!email || !password) {
            setError("Please fill out all fields")
            return
        }

        try {
            setError("")

            await login({
                email,
                password,
            })
        } catch {
            setError("Invalid credentials")
        }
    }

    return (
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
    )
}