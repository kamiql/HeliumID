import { Box, Button, Stack, TextField, Typography } from "@mui/material"
import CheckCircleOutlinedIcon from "@mui/icons-material/CheckCircleOutlined"
import { useEffect, useRef, useState } from "react"
import { Link } from "react-router"
import { useSearchParams } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { LoadingState } from "../../components/ui/StateView.tsx"
import { accountApi } from "../../api/account.ts"
import { useAuthStore } from "../../stores/auth.store.ts"
import { MONO_FONT } from "../../lib/theme.ts"

type Phase = "confirming" | "done" | "failed" | "manual"

/**
 * `/account/email-change/confirm?token=...` — the link mailed to the *new* address.
 *
 * The token proves control of the address being claimed, so this endpoint needs no session of
 * its own: the link may be opened in a different browser from the one that started the change.
 */
export default function ConfirmEmailChangePage() {
    const [searchParams] = useSearchParams()
    const token = searchParams.get("token")
    const user = useAuthStore((state) => state.user)
    const refresh = useAuthStore((state) => state.refresh)

    const [phase, setPhase] = useState<Phase>(token ? "confirming" : "manual")
    const [manualToken, setManualToken] = useState("")
    const [error, setError] = useState<unknown>(null)
    const attempted = useRef(false)

    const submit = (candidate: string) => {
        setPhase("confirming")
        accountApi
            .confirmEmailChange(candidate)
            .then(() => {
                setPhase("done")
                if (user) void refresh()
            })
            .catch((caught: unknown) => {
                setError(caught)
                setPhase("failed")
            })
    }

    useEffect(() => {
        if (!token || attempted.current) return
        attempted.current = true
        submit(token)
        // `submit` is stable enough for a one-shot confirmation keyed on the token.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token])

    const backTo = user ? "/account" : "/login"
    const backLabel = user ? "Back to account" : "Back to sign in"

    return (
        <AuthCard
            title={phase === "done" ? "Email updated" : "Confirm email"}
            statusIcon={phase === "done" ? <CheckCircleOutlinedIcon /> : undefined}
            statusTone="success"
            subtitle={
                phase === "manual"
                    ? "Paste the confirmation code from the email we sent to your new address."
                    : undefined
            }
        >
            {phase === "confirming" && <LoadingState label="Confirming your new address…" />}

            {phase === "done" && (
                <Stack spacing={3}>
                    <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                        Your email address has been updated.
                    </Typography>

                    <Button component={Link} to={backTo} fullWidth variant="contained">
                        {user ? "Back to account" : "Sign in"}
                    </Button>
                </Stack>
            )}

            {phase === "failed" && (
                <Stack spacing={2}>
                    <ErrorAlert error={error} />

                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                        That link is no longer valid. Start the email change again from your
                        account settings.
                    </Typography>

                    <Button component={Link} to={backTo} fullWidth variant="contained">
                        {backLabel}
                    </Button>
                </Stack>
            )}

            {phase === "manual" && (
                <Box
                    component="form"
                    onSubmit={(event) => {
                        event.preventDefault()
                        const candidate = manualToken.trim()
                        if (!candidate) return
                        submit(candidate)
                    }}
                >
                    <Stack spacing={2}>
                        <TextField
                            fullWidth
                            autoFocus
                            label="Confirmation code"
                            value={manualToken}
                            onChange={(event) => setManualToken(event.target.value)}
                            slotProps={{ input: { sx: { fontFamily: MONO_FONT } } }}
                        />

                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Nothing in your inbox? Check your spam folder, then start the email
                            change again from your account settings.
                        </Typography>

                        <Button
                            type="submit"
                            fullWidth
                            variant="contained"
                            disabled={manualToken.trim().length === 0}
                        >
                            Confirm
                        </Button>

                        <Button component={Link} to={backTo} fullWidth variant="text">
                            {backLabel}
                        </Button>
                    </Stack>
                </Box>
            )}
        </AuthCard>
    )
}
