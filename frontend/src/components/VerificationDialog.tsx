import {
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    TextField,
    Typography,
} from "@mui/material"
import { useState } from "react"
import { describeError } from "../api/problem.ts"

type VerificationDialogProps = {
    open: boolean
    title?: string
    description?: string
    label?: string
    onSubmit: (token: string) => Promise<void>
    onClose: () => void
    onCompleted: () => void
}

/**
 * Generic "paste the token from your email" dialog.
 *
 * Email confirmation is a single-use link token rather than a short numeric code: the token is
 * long and random, so it cannot be brute forced the way a six-digit code could, and it only
 * ever reaches the address being proven.
 */
export default function VerificationDialog({
    open,
    title = "Confirm your email",
    description = "Paste the confirmation code from the email we sent you.",
    label = "Confirmation code",
    onSubmit,
    onClose,
    onCompleted,
}: VerificationDialogProps) {
    const [token, setToken] = useState("")
    const [error, setError] = useState("")
    const [loading, setLoading] = useState(false)

    const handleSubmit = async () => {
        if (loading || token.trim().length === 0) return

        try {
            setLoading(true)
            setError("")
            await onSubmit(token.trim())
            setToken("")
            onCompleted()
        } catch (caught) {
            setError(describeError(caught))
        } finally {
            setLoading(false)
        }
    }

    return (
        <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs">
            <DialogTitle>{title}</DialogTitle>

            <DialogContent>
                <Stack spacing={3}>
                    <Typography sx={{ color: "text.secondary" }}>{description}</Typography>

                    <TextField
                        fullWidth
                        autoFocus
                        label={label}
                        value={token}
                        onChange={(event) => {
                            setToken(event.target.value)
                            setError("")
                        }}
                        onKeyDown={(event) => {
                            if (event.key === "Enter") void handleSubmit()
                        }}
                    />

                    {error && (
                        <Typography color="error" variant="body2">
                            {error}
                        </Typography>
                    )}
                </Stack>
            </DialogContent>

            <DialogActions>
                <Button onClick={onClose} disabled={loading}>
                    Close
                </Button>

                <Button
                    variant="contained"
                    onClick={() => void handleSubmit()}
                    disabled={loading || token.trim().length === 0}
                >
                    Confirm
                </Button>
            </DialogActions>
        </Dialog>
    )
}
