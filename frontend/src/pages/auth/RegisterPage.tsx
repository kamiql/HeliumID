import {
    Alert,
    Box,
    Button,
    Link as MuiLink,
    Stack,
    Step,
    StepLabel,
    Stepper,
    TextField,
    Typography,
} from "@mui/material"
import MarkEmailReadOutlinedIcon from "@mui/icons-material/MarkEmailReadOutlined"
import { useState } from "react"
import { Link } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import EmailField from "../../components/EmailField.tsx"
import PasswordField from "../../components/PasswordField.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { useAuth } from "../../hooks/useAuth.ts"
import { describeFieldError, toHeliumError } from "../../api/problem.ts"
import { evaluatePassword, usePasswordRequirements } from "../../hooks/usePasswordRequirements.ts"

const STEPS = ["Your details", "Sign-in credentials"]

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
            <AuthCard
                statusIcon={<MarkEmailReadOutlinedIcon />}
                statusTone="success"
                title="Check your inbox"
            >
                <Stack spacing={3}>
                    <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                        If that address can be registered, we have sent a verification link to{" "}
                        <Box component="strong" sx={{ wordBreak: "break-word" }}>
                            {email}
                        </Box>
                        . Open it to finish setting up your account.
                    </Typography>

                    <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center" }}>
                        Nothing after a few minutes? Check your spam folder, then request a new
                        link from the sign-in page.
                    </Typography>

                    <Button component={Link} to="/login" fullWidth variant="contained">
                        Back to sign in
                    </Button>
                </Stack>
            </AuthCard>
        )
    }

    // Both guards reject the form locally, before any request. An error raised while those
    // fields are incomplete is the local one and belongs on the fields, not in a banner.
    const detailsIncomplete = error !== null && !username
    const credentialsIncomplete =
        error !== null && (!email || !password || password !== passwordConfirm)

    return (
        <AuthCard
            title="Create your account"
            subtitle="Two short steps — details first, then how you sign in."
            footer={
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    Already have an account?{" "}
                    <MuiLink component={Link} to="/login">
                        Sign in
                    </MuiLink>
                </Typography>
            }
        >
            <Stepper activeStep={step - 1} sx={{ mb: 3 }}>
                {STEPS.map((label) => (
                    <Step key={label}>
                        <StepLabel>{label}</StepLabel>
                    </Step>
                ))}
            </Stepper>

            <Box
                component="form"
                onSubmit={(event) => {
                    event.preventDefault()
                    if (step === 2) void handleRegister()
                }}
            >
                {step === 1 && (
                    <Stack spacing={2}>
                        <TextField
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
                            error={Boolean(fieldErrors.username) || detailsIncomplete}
                            helperText={
                                fieldErrors.username
                                    ? describeFieldError(fieldErrors.username)
                                    : detailsIncomplete
                                      ? "Choose a username."
                                      : undefined
                            }
                        />

                        <TextField
                            fullWidth
                            label="First name"
                            autoComplete="given-name"
                            value={firstName}
                            onChange={(event) => {
                                setFirstName(event.target.value)
                                clearErrors()
                            }}
                            error={Boolean(fieldErrors.firstName)}
                            helperText={
                                fieldErrors.firstName
                                    ? describeFieldError(fieldErrors.firstName)
                                    : undefined
                            }
                        />

                        <TextField
                            fullWidth
                            label="Last name"
                            autoComplete="family-name"
                            value={lastName}
                            onChange={(event) => {
                                setLastName(event.target.value)
                                clearErrors()
                            }}
                        />

                        {error !== null && !detailsIncomplete && <ErrorAlert error={error} />}

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
                        >
                            Continue
                        </Button>
                    </Stack>
                )}

                {step === 2 && (
                    <Stack spacing={2}>
                        <EmailField
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
                            error={Boolean(fieldErrors.email) || (credentialsIncomplete && !email)}
                            helperText={
                                fieldErrors.email
                                    ? describeFieldError(fieldErrors.email)
                                    : credentialsIncomplete && !email
                                      ? "Enter the address we should verify."
                                      : undefined
                            }
                        />

                        <PasswordField
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

                        {/* A server-side reason the checklist cannot derive, e.g. a breach hit. */}
                        {fieldErrors.password && (
                            <Alert severity="error">
                                {describeFieldError(fieldErrors.password)}
                            </Alert>
                        )}

                        <PasswordField
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

                        {error !== null && !credentialsIncomplete && (
                            <ErrorAlert error={error} hideFieldErrors />
                        )}

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
                    </Stack>
                )}
            </Box>
        </AuthCard>
    )
}
