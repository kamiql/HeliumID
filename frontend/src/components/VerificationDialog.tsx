import {
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    LinearProgress,
    Stack,
    Typography,
} from "@mui/material"
import {useEffect, useState} from "react"
import type {AxiosError} from "axios"
import {verificationApi} from "../api/user.ts"

type VerificationDialogProps = {
    open: boolean
    verificationId: string | null
    onClose: () => void
    onCompleted: () => void
}

type VerificationErrorResponse = {
    message?: string
}

export default function VerificationDialog({
                                               open,
                                               verificationId,
                                               onClose,
                                               onCompleted,
                                           }: VerificationDialogProps) {
    const [remainingSeconds, setRemainingSeconds] = useState(300)
    const [error, setError] = useState("")

    useEffect(() => {
        if (!open || !verificationId) {
            return
        }

        let active = true

        const poll = async () => {
            while (active) {
                await new Promise((resolve) => setTimeout(resolve, 2000))

                if (!active) {
                    return
                }

                try {
                    const response = await verificationApi.status(
                        verificationId,
                    )

                    if (response.status === 200) {
                        onCompleted()
                        return
                    }
                } catch (error) {
                    const axiosError = error as AxiosError<VerificationErrorResponse>

                    if (axiosError.response?.status === 410) {
                        setError("Verification timed out")
                        return
                    }

                    if (axiosError.response?.status === 404) {
                        setError("Verification not found")
                        return
                    }

                    setError("Failed to check verification status")
                    return
                }
            }
        }

        poll()

        return () => {
            active = false
        }
    }, [open, verificationId, onCompleted])

    useEffect(() => {
        if (!open || !verificationId) {
            return
        }

        const interval = setInterval(() => {
            setRemainingSeconds((seconds) => {
                if (seconds <= 1) {
                    clearInterval(interval)
                    return 0
                }

                return seconds - 1
            })
        }, 1000)

        return () => clearInterval(interval)
    }, [open, verificationId])

    const minutes = Math.floor(remainingSeconds / 60)
    const seconds = remainingSeconds % 60

    return (
        <Dialog
            open={open}
            onClose={onClose}
            fullWidth
            maxWidth="xs"
        >
            <DialogTitle>Email verification</DialogTitle>

            <DialogContent>
                <Stack spacing={3}>
                    <Typography
                        sx={{
                            color: "text.secondary",
                        }}
                    >
                        Check your inbox and follow the verification link in
                        the email.
                    </Typography>

                    <Typography
                        variant="h4"
                        align="center"
                        sx={{
                            fontVariantNumeric: "tabular-nums",
                            fontWeight: 700,
                        }}
                    >
                        {minutes}:{seconds.toString().padStart(2, "0")}
                    </Typography>

                    <LinearProgress
                        variant="determinate"
                        value={(remainingSeconds / 300) * 100}
                    />

                    {error && (
                        <Typography
                            color="error"
                            variant="body2"
                        >
                            {error}
                        </Typography>
                    )}
                </Stack>
            </DialogContent>

            <DialogActions>
                <Button onClick={onClose}>
                    Close
                </Button>
            </DialogActions>
        </Dialog>
    )
}