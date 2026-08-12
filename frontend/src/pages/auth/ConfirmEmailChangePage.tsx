import { Button, CircularProgress, Stack, TextField, Typography } from "@mui/material"
import MarkEmailReadOutlinedIcon from "@mui/icons-material/MarkEmailReadOutlined"
import { useEffect, useRef, useState } from "react"
import { Link } from "react-router"
import { useSearchParams } from "react-router"
import AuthCard from "../../components/auth/AuthCard.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { accountApi } from "../../api/account.ts"
import { useAuthStore } from "../../stores/auth.store.ts"

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

    return (
        <AuthCard
            icon={<MarkEmailReadOutlinedIcon />}
            title="Confirm email"
            iconColor={phase === "done" ? "success.main" : "primary.main"}
        >
            <Stack spacing={2}>
                {phase === "confirming" && (
                    <Stack spacing={2} sx={{ alignItems: "center" }}>
                        <CircularProgress />
                        <Typography sx={{ color: "text.secondary" }}>
                            Confirming your new address…
                        </Typography>
                    </Stack>
                )}

                {phase === "done" && (
                    <>
                        <Typography sx={{ color: "text.secondary", textAlign: "center" }}>
                            Your email address has been updated.
                        </Typography>

                        <Button component={Link} to={user ? "/account" : "/login"} fullWidth variant="contained">
                            {user ? "Back to account" : "Sign in"}
                        </Button>
                    </>
                )}

                {(phase === "failed" || phase === "manual") && (
                    <>
                        {phase === "failed" && <ErrorAlert error={error} />}

                        <Typography sx={{ color: "text.secondary" }}>
                            {phase === "failed"
                                ? "That link is no longer valid. Start the email change again from your account settings."
                                : "Paste the confirmation code from the email we sent to your new address."}
                        </Typography>

                        {phase === "manual" && (
                            <>
                                <TextField
                                    fullWidth
                                    autoFocus
                                    label="Confirmation code"
                                    value={manualToken}
                                    onChange={(event) => setManualToken(event.target.value)}
                                />

                                <Button
                                    fullWidth
                                    variant="contained"
                                    disabled={manualToken.trim().length === 0}
                                    onClick={() => submit(manualToken.trim())}
                                >
                                    Confirm
                                </Button>
                            </>
                        )}

                        <Button
                            component={Link}
                            to={user ? "/account" : "/login"}
                            fullWidth
                            variant="text"
                        >
                            {user ? "Back to account" : "Back to sign in"}
                        </Button>
                    </>
                )}
            </Stack>
        </AuthCard>
    )
}
