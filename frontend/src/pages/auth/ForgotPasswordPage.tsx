import { Box, Button, Stack, Typography } from "@mui/material"
import MarkEmailReadOutlinedIcon from "@mui/icons-material/MarkEmailReadOutlined"
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

    if (sent) {
        return (
            <AuthCard
                statusIcon={<MarkEmailReadOutlinedIcon />}
                statusTone="success"
                title="Check your inbox"
            >
                <Stack spacing={3}>
                    <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                        If an account exists for{" "}
                        <Box component="strong" sx={{ wordBreak: "break-word" }}>
                            {email}
                        </Box>
                        , a reset link is on its way. The link expires shortly and can be used
                        once.
                    </Typography>

                    <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center" }}>
                        Nothing after a few minutes? Check your spam folder, then try again with
                        the address you signed up with.
                    </Typography>

                    <Button component={Link} to="/login" fullWidth variant="contained">
                        Back to sign in
                    </Button>
                </Stack>
            </AuthCard>
        )
    }

    return (
        <AuthCard
            title="Reset password"
            subtitle="Enter the email address on your account and we will send you a link to choose a new password."
        >
            <Box
                component="form"
                onSubmit={(event) => {
                    event.preventDefault()
                    void handleSubmit()
                }}
            >
                <Stack spacing={2}>
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
                        type="submit"
                        fullWidth
                        variant="contained"
                        disabled={loading || !email}
                    >
                        Send reset link
                    </Button>

                    <Button component={Link} to="/login" fullWidth variant="text">
                        Back to sign in
                    </Button>
                </Stack>
            </Box>
        </AuthCard>
    )
}
