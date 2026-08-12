import { Alert, Button, Stack, TextField, Typography } from "@mui/material"
import LockResetOutlinedIcon from "@mui/icons-material/LockResetOutlined"
import { useState } from "react"
import { Link, useSearchParams } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import PasswordField from "../../components/PasswordField.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { authApi } from "../../api/auth.ts"
import { describeFieldError, toHeliumError } from "../../api/problem.ts"
import { evaluatePassword, usePasswordRequirements } from "../../hooks/usePasswordRequirements.ts"

/**
 * `/reset-password?token=...`
 *
 * Completing a reset never issues a session: mailbox control is not proof of identity, so the
 * user is sent to the sign-in page to authenticate with their new password.
 */
export default function ResetPasswordPage() {
    const [searchParams] = useSearchParams()
    const requirements = usePasswordRequirements()

    const [token, setToken] = useState(searchParams.get("token") ?? "")
    const [password, setPassword] = useState("")
    const [confirm, setConfirm] = useState("")
    const [error, setError] = useState<unknown>(null)
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
    const [loading, setLoading] = useState(false)
    const [done, setDone] = useState(false)

    const checks = evaluatePassword(requirements, password)
    const policyMet = checks.every((check) => check.satisfied !== false)

    const handleSubmit = async () => {
        if (loading || !token || !password || password !== confirm) return

        try {
            setLoading(true)
            setError(null)
            setFieldErrors({})
            await authApi.completePasswordReset({ token, new_password: password })
            setDone(true)
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            setFieldErrors(heliumError.fieldErrors)
            setError(heliumError)
        } finally {
            setLoading(false)
        }
    }

    if (done) {
        return (
            <AuthCard icon={<LockResetOutlinedIcon />} title="Password set" iconColor="success.main">
                <Stack spacing={2}>
                    <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                        Your password has been changed and every other session was signed out.
                        Sign in with your new password.
                    </Typography>

                    <Button component={Link} to="/login" fullWidth variant="contained">
                        Continue to sign in
                    </Button>
                </Stack>
            </AuthCard>
        )
    }

    return (
        <AuthCard icon={<LockResetOutlinedIcon />} title="New password">
            <Stack spacing={2}>
                {!searchParams.get("token") && (
                    <>
                        <Alert severity="info">
                            Paste the reset code from your email to continue.
                        </Alert>

                        <TextField
                            fullWidth
                            label="Reset code"
                            value={token}
                            onChange={(event) => {
                                setToken(event.target.value)
                                setError(null)
                            }}
                        />
                    </>
                )}

                <PasswordField
                    fullWidth
                    required
                    autoFocus
                    label="New password"
                    autoComplete="new-password"
                    value={password}
                    onType={(value) => {
                        setPassword(value)
                        setError(null)
                    }}
                    validate
                    error={Boolean(fieldErrors.new_password || fieldErrors.password)}
                />

                {(fieldErrors.new_password || fieldErrors.password) && (
                    <Alert severity="error">
                        {describeFieldError(fieldErrors.new_password ?? fieldErrors.password)}
                    </Alert>
                )}

                <PasswordField
                    fullWidth
                    required
                    label="Confirm new password"
                    autoComplete="new-password"
                    value={confirm}
                    onType={(value) => {
                        setConfirm(value)
                        setError(null)
                    }}
                    matches={password}
                    validate
                />

                {error !== null && <ErrorAlert error={error} hideFieldErrors />}

                <Button
                    fullWidth
                    variant="contained"
                    disabled={loading || !token || !policyMet || !password || password !== confirm}
                    onClick={() => void handleSubmit()}
                    sx={{ py: 1.2 }}
                >
                    Set new password
                </Button>

                <Button component={Link} to="/login" fullWidth variant="text">
                    Back to sign in
                </Button>
            </Stack>
        </AuthCard>
    )
}
