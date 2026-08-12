import { Button, Stack, Typography } from "@mui/material"
import LockResetOutlinedIcon from "@mui/icons-material/LockResetOutlined"
import { useState } from "react"
import { Link } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import EmailField from "../../components/EmailField.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { authApi } from "../../api/auth.ts"

export default function ForgotPasswordPage() {
    const [email, setEmail] = useState("")
    const [sent, setSent] = useState(false)
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(false)

    const handleSubmit = async () => {
        if (!email || loading) return

        try {
            setLoading(true)
            setError(null)
            await authApi.requestPasswordReset(email)
            // The response is `202` whether or not the address exists, and this screen must be
            // identical either way — otherwise it becomes an account-enumeration oracle.
            setSent(true)
        } catch (caught) {
            setError(caught)
        } finally {
            setLoading(false)
        }
    }

    return (
        <AuthCard
            icon={<LockResetOutlinedIcon />}
            title="Reset password"
            iconColor={sent ? "success.main" : "primary.main"}
        >
            <Stack spacing={2}>
                {sent ? (
                    <>
                        <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                            If an account exists for <strong>{email}</strong>, a reset link is on
                            its way. The link expires shortly and can be used once.
                        </Typography>

                        <Button component={Link} to="/login" fullWidth variant="contained">
                            Back to sign in
                        </Button>
                    </>
                ) : (
                    <>
                        <Typography sx={{ color: "text.secondary" }}>
                            Enter the email address on your account and we will send you a link to
                            choose a new password.
                        </Typography>

                        <EmailField
                            fullWidth
                            required
                            autoFocus
                            label="Email"
                            autoComplete="email"
                            value={email}
                            onType={(value) => {
                                setEmail(value)
                                setError(null)
                            }}
                        />

                        {error !== null && <ErrorAlert error={error} />}

                        <Button
                            fullWidth
                            variant="contained"
                            disabled={loading || !email}
                            onClick={() => void handleSubmit()}
                            sx={{ py: 1.2 }}
                        >
                            Send reset link
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
