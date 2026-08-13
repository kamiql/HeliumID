import {
    Button,
    CircularProgress,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    Stack,
    TextField,
} from "@mui/material"
import { useId, useState } from "react"
import ErrorAlert from "./ErrorAlert.tsx"
import { MONO_FONT } from "../lib/theme.ts"

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
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(false)

    const titleId = useId()
    const descriptionId = useId()

    const handleSubmit = async () => {
        if (loading || token.trim().length === 0) return

        try {
            setLoading(true)
            setError(null)
            await onSubmit(token.trim())
            setToken("")
            onCompleted()
        } catch (caught) {
            setError(caught)
        } finally {
            setLoading(false)
        }
    }

    return (
        <Dialog
            open={open}
            onClose={onClose}
            fullWidth
            maxWidth="xs"
            aria-labelledby={titleId}
            aria-describedby={descriptionId}
        >
            <DialogTitle id={titleId}>{title}</DialogTitle>

            <DialogContent>
                <Stack spacing={2.5}>
                    <DialogContentText id={descriptionId} variant="body2">
                        {description}
                    </DialogContentText>

                    <TextField
                        fullWidth
                        autoFocus
                        label={label}
                        value={token}
                        onChange={(event) => {
                            setToken(event.target.value)
                            setError(null)
                        }}
                        onKeyDown={(event) => {
                            if (event.key === "Enter") void handleSubmit()
                        }}
                        // The token is a long random string, so a fixed-width face makes a
                        // mistyped or half-pasted character visible.
                        slotProps={{ input: { sx: { fontFamily: MONO_FONT } } }}
                        helperText="Nothing in your inbox? Check the spam folder — the code expires after a short time, and you can request a new one."
                    />

                    {error !== null && <ErrorAlert error={error} />}
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
                    startIcon={loading ? <CircularProgress size={16} color="inherit" /> : undefined}
                >
                    Confirm
                </Button>
            </DialogActions>
        </Dialog>
    )
}
