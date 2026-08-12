import {
    Alert,
    Avatar,
    Box,
    Button,
    Container,
    Link as MuiLink,
    Paper,
    TextField,
    Typography,
} from "@mui/material"
import PersonAddOutlinedIcon from "@mui/icons-material/PersonAddOutlined"
import MarkEmailReadOutlinedIcon from "@mui/icons-material/MarkEmailReadOutlined"
import { useState } from "react"
import { Link } from "react-router"
import EmailField from "../../components/EmailField.tsx"
import PasswordField from "../../components/PasswordField.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { useAuth } from "../../hooks/useAuth.ts"
import { describeFieldError, toHeliumError } from "../../api/problem.ts"
import { evaluatePassword, usePasswordRequirements } from "../../hooks/usePasswordRequirements.ts"

export default function RegisterPage() {
    const { register, loading } = useAuth()
    const requirements = usePasswordRequirements()

    const [step, setStep] = useState(1)
    const [submitted, setSubmitted] = useState(false)
    const [error, setError] = useState<unknown>(null)
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

    const [username, setUsername] = useState("")
    const [firstName, setFirstName] = useState("")
    const [lastName, setLastName] = useState("")
    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")
    const [passwordConfirm, setPasswordConfirm] = useState("")

    const checks = evaluatePassword(requirements, password, [username, email])
    const policyMet = checks.every((check) => check.satisfied !== false)

    const clearErrors = () => {
        setError(null)
        setFieldErrors({})
    }

    const handleRegister = async () => {
        if (!email || !password || password !== passwordConfirm) {
            setError(new Error("incomplete"))
            return
        }

        try {
            clearErrors()
            await register({ username, email, password, firstName, lastName })
            // 202 with an opaque body whether or not the address was already taken, so this
            // screen must look identical either way — it must not confirm the address exists.
            setSubmitted(true)
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            setFieldErrors(heliumError.fieldErrors)
            setError(heliumError)
            if (heliumError.fieldErrors.username || heliumError.fieldErrors.firstName) {
                setStep(1)
            }
        }
    }

    if (submitted) {
        return (
            <Container component="main" maxWidth="xs">
                <Paper
                    elevation={8}
                    sx={{ p: 4, width: "100%", borderRadius: 3, backgroundColor: "background.paper" }}
                >
                    <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                        <Avatar sx={{ mb: 2, bgcolor: "success.main" }}>
                            <MarkEmailReadOutlinedIcon />
                        </Avatar>

                        <Typography
                            component="h1"
                            variant="h4"
                            sx={{ fontFamily: "Silkscreen", mb: 3, textAlign: "center" }}
                        >
                            Check your inbox
                        </Typography>

                        <Typography sx={{ color: "text.secondary", textAlign: "center", mb: 3 }}>
                            If that address can be registered, we have sent a verification link to{" "}
                            <strong>{email}</strong>. Open it to finish setting up your account.
                        </Typography>

                        <Button component={Link} to="/login" fullWidth variant="contained">
                            Back to sign in
                        </Button>
                    </Box>
                </Paper>
            </Container>
        )
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

                    <Box
                        component="form"
                        sx={{ width: "100%" }}
                        onSubmit={(event) => {
                            event.preventDefault()
                            if (step === 2) void handleRegister()
                        }}
                    >
                        {step === 1 && (
                            <>
                                <TextField
                                    margin="normal"
                                    required
                                    fullWidth
                                    label="Username"
                                    autoComplete="username"
                                    autoFocus
                                    value={username}
                                    onChange={(event) => {
                                        setUsername(event.target.value)
                                        clearErrors()
                                    }}
                                    error={Boolean(fieldErrors.username)}
                                    helperText={
                                        fieldErrors.username
                                            ? describeFieldError(fieldErrors.username)
                                            : undefined
                                    }
                                />

                                <TextField
                                    margin="normal"
                                    fullWidth
                                    label="First name"
                                    autoComplete="given-name"
                                    value={firstName}
                                    onChange={(event) => {
                                        setFirstName(event.target.value)
                                        clearErrors()
                                    }}
                                />

                                <TextField
                                    margin="normal"
                                    fullWidth
                                    label="Last name"
                                    autoComplete="family-name"
                                    value={lastName}
                                    onChange={(event) => {
                                        setLastName(event.target.value)
                                        clearErrors()
                                    }}
                                />

                                {error !== null && <ErrorAlert error={error} sx={{ mt: 2 }} />}

                                <Button
                                    fullWidth
                                    variant="contained"
                                    onClick={() => {
                                        if (!username) {
                                            setError(new Error("incomplete"))
                                            return
                                        }
                                        clearErrors()
                                        setStep(2)
                                    }}
                                    sx={{
                                        mt: 2,
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
                                        clearErrors()
                                    }}
                                    error={Boolean(fieldErrors.email)}
                                    helperText={
                                        fieldErrors.email
                                            ? describeFieldError(fieldErrors.email)
                                            : undefined
                                    }
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
                                        clearErrors()
                                    }}
                                    validate
                                    identifiers={[username, email]}
                                    error={Boolean(fieldErrors.password)}
                                />

                                {fieldErrors.password && (
                                    <Alert severity="error" sx={{ mt: 1 }}>
                                        {describeFieldError(fieldErrors.password)}
                                    </Alert>
                                )}

                                <PasswordField
                                    margin="normal"
                                    required
                                    fullWidth
                                    label="Confirm password"
                                    autoComplete="new-password"
                                    value={passwordConfirm}
                                    onType={(value) => {
                                        setPasswordConfirm(value)
                                        clearErrors()
                                    }}
                                    matches={password}
                                    validate
                                />

                                {error !== null && <ErrorAlert error={error} hideFieldErrors sx={{ mt: 2 }} />}

                                <Button
                                    type="submit"
                                    fullWidth
                                    variant="contained"
                                    disabled={
                                        loading ||
                                        !policyMet ||
                                        password.length === 0 ||
                                        password !== passwordConfirm
                                    }
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
                                        clearErrors()
                                        setStep(1)
                                    }}
                                >
                                    Back
                                </Button>
                            </>
                        )}

                        <Typography sx={{ textAlign: "center", mt: 2 }}>
                            Already have an account?{" "}
                            <MuiLink component={Link} to="/login" variant="body2">
                                Sign in
                            </MuiLink>
                        </Typography>
                    </Box>
                </Box>
            </Paper>
        </Container>
    )
}
