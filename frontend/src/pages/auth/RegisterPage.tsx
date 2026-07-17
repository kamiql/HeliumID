import {
    Avatar,
    Box,
    Button,
    Container,
    Link,
    Paper,
    Typography,
} from "@mui/material"
import PersonAddOutlinedIcon from "@mui/icons-material/PersonAddOutlined"
import { useState } from "react"
import EmailField from "../../components/EmailField.tsx"
import PasswordField from "../../components/PasswordField.tsx"
import {useAuth} from "../../hooks/useAuth.ts";
import axios from "axios";

export default function RegisterPage() {
    const { register, login, loading } = useAuth()

    const [step, setStep] = useState(1)
    const [error, setError] = useState("")

    const [username, setUsername] = useState("")
    const [firstName, setFirstName] = useState("")
    const [lastName, setLastName] = useState("")

    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")
    const [passwordConfirm, setPasswordConfirm] = useState("")

    const handleRegister = async () => {
        if (!email || !password || !passwordConfirm) {
            setError("Please fill out all fields")
            return
        }

        try {
            setError("")

            await register({
                username,
                firstName,
                lastName,
                email,
                password,
            }).then(async () => {
                await login({
                    email,
                    password
                })
            })
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 409) {
                setError(error.response.data)
                return
            }

            setError("Failed to create account")
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
                        <PersonAddOutlinedIcon />
                    </Avatar>

                    <Typography
                        component="h1"
                        variant="h4"
                        sx={{
                            fontFamily: "Silkscreen",
                            mb: 3,
                        }}
                    >
                        Sign up
                    </Typography>

                    <Box component="form" sx={{ width: "100%" }}>
                        {step === 1 && (
                            <>
                                <Box
                                    component="input"
                                    placeholder="Username"
                                    value={username}
                                    onChange={(event) => {
                                        setUsername(event.target.value)
                                        setError("")
                                    }}
                                    sx={{
                                        width: "100%",
                                        mb: 2,
                                        p: 1.8,
                                        borderRadius: 1,
                                        border: "1px solid",
                                        borderColor: error && !username
                                            ? "error.main"
                                            : "divider",
                                        background: "transparent",
                                        color: "text.primary",
                                        fontSize: "1rem",
                                    }}
                                />

                                <Box
                                    component="input"
                                    placeholder="First name"
                                    value={firstName}
                                    onChange={(event) => {
                                        setFirstName(event.target.value)
                                        setError("")
                                    }}
                                    sx={{
                                        width: "100%",
                                        mb: 2,
                                        p: 1.8,
                                        borderRadius: 1,
                                        border: "1px solid",
                                        borderColor: error && !firstName
                                            ? "error.main"
                                            : "divider",
                                        background: "transparent",
                                        color: "text.primary",
                                        fontSize: "1rem",
                                    }}
                                />

                                <Box
                                    component="input"
                                    placeholder="Last name"
                                    value={lastName}
                                    onChange={(event) => {
                                        setLastName(event.target.value)
                                        setError("")
                                    }}
                                    sx={{
                                        width: "100%",
                                        mb: 2,
                                        p: 1.8,
                                        borderRadius: 1,
                                        border: "1px solid",
                                        borderColor: error && !lastName
                                            ? "error.main"
                                            : "divider",
                                        background: "transparent",
                                        color: "text.primary",
                                        fontSize: "1rem",
                                    }}
                                />

                                {error && (
                                    <Typography
                                        color="error"
                                        variant="body2"
                                        sx={{ mb: 2 }}
                                    >
                                        {error}
                                    </Typography>
                                )}

                                <Button
                                    fullWidth
                                    variant="contained"
                                    onClick={() => {
                                        if (!username || !firstName || !lastName) {
                                            setError("Please fill out all fields")
                                            return
                                        }

                                        setError("")
                                        setStep(2)
                                    }}
                                    sx={{
                                        mt: 1,
                                        py: 1.2,
                                    }}
                                >
                                    Continue
                                </Button>
                            </>
                        )}

                        {step === 2 && (
                            <>
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
                                    helperText={!!error && !email ? error : undefined}
                                />

                                <PasswordField
                                    margin="normal"
                                    required
                                    fullWidth
                                    label="Password"
                                    autoComplete="new-password"
                                    value={password}
                                    onType={(value) => {
                                        setPassword(value)
                                        setError("")
                                    }}
                                    validate
                                    error={!!error && !password}
                                    helperText={!!error && !password ? error : undefined}
                                />

                                <PasswordField
                                    margin="normal"
                                    required
                                    fullWidth
                                    label="Confirm password"
                                    autoComplete="new-password"
                                    value={passwordConfirm}
                                    onType={(value) => {
                                        setPasswordConfirm(value)
                                        setError("")
                                    }}
                                    matches={password}
                                    validate
                                    error={!!error && !passwordConfirm}
                                    helperText={
                                        !!error && !passwordConfirm
                                            ? error
                                            : undefined
                                    }
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
                                    onClick={handleRegister}
                                    sx={{
                                        mt: 2,
                                        mb: 2,
                                        py: 1.2,
                                    }}
                                >
                                    Create account
                                </Button>

                                <Button
                                    fullWidth
                                    variant="text"
                                    onClick={() => {
                                        setError("")
                                        setStep(1)
                                    }}
                                >
                                    Back
                                </Button>
                            </>
                        )}

                        <Typography sx={{ textAlign: "center", mt: 2 }}>
                            Already have an account?{" "}
                            <Link
                                href="/login"
                                variant="body2"
                            >
                                Sign in
                            </Link>
                        </Typography>
                    </Box>
                </Box>
            </Paper>
        </Container>
    )
}