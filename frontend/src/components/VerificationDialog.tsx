import {
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    Typography,
} from "@mui/material"
import {useState} from "react"
import type {AxiosError} from "axios"
import {verificationApi} from "../api/user.ts"
import OtpInput from "./OtpInput.tsx"

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
    const [code, setCode] = useState("")
    const [error, setError] = useState("")
    const [loading, setLoading] = useState(false)

    const handleVerify = async (verificationCode = code) => {
        if (!verificationId || verificationCode.length !== 6 || loading) {
            return
        }

        try {
            setLoading(true)
            setError("")

            await verificationApi.verify(
                verificationId,
                verificationCode,
            )

            onCompleted()
        } catch (error) {
            const axiosError = error as AxiosError<VerificationErrorResponse>

            if (axiosError.response?.status === 400) {
                setError("Invalid or expired verification code")
            } else {
                setError(
                    axiosError.response?.data?.message ||
                    "Failed to verify code",
                )
            }
        } finally {
            setLoading(false)
        }
    }

    const handleCodeChange = (value: string) => {
        setCode(value)

        if (value.length === 6) {
            void handleVerify(value)
        }
    }

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
                        Enter the 6-digit code.
                    </Typography>

                    <OtpInput
                        value={code}
                        onChange={handleCodeChange}
                        autoFocus
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
                <Button
                    onClick={onClose}
                    disabled={loading}
                >
                    Close
                </Button>

                <Button
                    variant="contained"
                    onClick={() => void handleVerify()}
                    disabled={
                        loading ||
                        code.length !== 6
                    }
                >
                    Verify
                </Button>
            </DialogActions>
        </Dialog>
    )
}