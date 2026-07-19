import {
    Alert,
    Box,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    Typography,
} from "@mui/material"
import {useState} from "react"
import axios from "axios"
import {useUser} from "../../../../hooks/useUser.ts"
import {useAuthStore} from "../../../../stores/auth.store.ts"
import {userApi} from "../../../../api/user.ts"
import OtpInput from "../../../../components/OtpInput.tsx"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx";
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx";

export default function TotpBox() {
    const user = useUser()
    const initialize = useAuthStore((state) => state.initialize)

    const [open, setOpen] = useState(false)
    const [disableOpen, setDisableOpen] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState("")

    const [qrCode, setQrCode] = useState("")
    const [code, setCode] = useState("")
    const [disableCode, setDisableCode] = useState("")

    const handleSetup = async () => {
        try {
            setLoading(true)
            setError("")

            const response = await userApi.setupTotp()

            setQrCode(response.data.qrCode)
            setCode("")
            setOpen(true)
        } catch {
            setError("Failed to setup two-factor authentication")
        } finally {
            setLoading(false)
        }
    }

    const handleEnable = async (value = code) => {
        if (value.length !== 6 || loading) return

        try {
            setLoading(true)
            setError("")

            await userApi.enableTotp({
                code: value,
            })

            setOpen(false)
            setCode("")
            setQrCode("")

            await initialize()
        } catch (error) {
            if (
                axios.isAxiosError(error) &&
                error.response?.status === 401
            ) {
                setError("Invalid authentication code")
                return
            }

            setError("Failed to enable two-factor authentication")
        } finally {
            setLoading(false)
        }
    }

    const handleDisable = async (value = disableCode) => {
        if (value.length !== 6 || loading) return

        try {
            setLoading(true)
            setError("")

            await userApi.disableTotp({
                code: value,
            })

            setDisableOpen(false)
            setDisableCode("")

            await initialize()
        } catch (error) {
            if (
                axios.isAxiosError(error) &&
                error.response?.status === 401
            ) {
                setError("Invalid authentication code")
                return
            }

            setError("Failed to disable two-factor authentication")
        } finally {
            setLoading(false)
        }
    }

    return (
        <>
            <AccountBox
                title="Two-factor authentication"
                description="Protect your account with an authenticator app."
                requirements={[
                    {
                        id: "email",
                        label: "Email verification required",
                        satisfied: user.emailVerified || user.totpEnabled,
                    },
                ]}
                sx={{
                    flex: "1 1 100%",
                }}
            >
                <Chip
                    label={
                        user.totpEnabled
                            ? "Enabled"
                            : "Not enabled"
                    }
                    color={
                        user.totpEnabled
                            ? "success"
                            : "warning"
                    }
                    variant="outlined"
                    sx={{
                        width: "fit-content",
                    }}
                />

                {user.totpEnabled ? (
                    <AccountButton
                        variant="outlined"
                        color="error"
                        onClick={() => {
                            setError("")
                            setDisableCode("")
                            setDisableOpen(true)
                        }}
                    >
                        Disable two-factor authentication
                    </AccountButton>
                ) : (
                    <AccountButton
                        variant="outlined"
                        onClick={handleSetup}
                        disabled={loading}
                    >
                        Setup two-factor authentication
                    </AccountButton>
                )}
            </AccountBox>

            <Dialog
                open={open}
                onClose={() => {
                    if (loading) return

                    setOpen(false)
                    setError("")
                    setCode("")
                    setQrCode("")
                }}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>
                    Setup two-factor authentication
                </DialogTitle>

                <DialogContent>
                    <Stack spacing={2}>
                        <Typography variant="body2">
                            Scan this QR code with your authenticator app and enter the generated code.
                        </Typography>

                        {qrCode && (
                            <Box
                                component="img"
                                src={qrCode}
                                alt="TOTP QR code"
                                sx={{
                                    width: 220,
                                    height: 220,
                                    mx: "auto",
                                }}
                            />
                        )}

                        <OtpInput
                            value={code}
                            onChange={(value) => {
                                setCode(value)
                                setError("")

                                if (value.length === 6) {
                                    void handleEnable(value)
                                }
                            }}
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
                    <AccountButton
                        onClick={() => setOpen(false)}
                        disabled={loading}
                    >
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        onClick={() => void handleEnable()}
                        disabled={
                            loading ||
                            code.length !== 6
                        }
                    >
                        Enable
                    </AccountButton>
                </DialogActions>
            </Dialog>

            <Dialog
                open={disableOpen}
                onClose={() => {
                    if (loading) return

                    setDisableOpen(false)
                    setDisableCode("")
                    setError("")
                }}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>
                    Disable two-factor authentication
                </DialogTitle>

                <DialogContent>
                    <Stack spacing={2}>
                        <Alert severity="warning">
                            Enter your current authenticator code to disable two-factor authentication.
                        </Alert>

                        <OtpInput
                            value={disableCode}
                            onChange={(value) => {
                                setDisableCode(value)
                                setError("")

                                if (value.length === 6) {
                                    void handleDisable(value)
                                }
                            }}
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
                    <AccountButton
                        onClick={() => setDisableOpen(false)}
                        disabled={loading}
                    >
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        color="error"
                        onClick={() => void handleDisable()}
                        disabled={
                            loading ||
                            disableCode.length !== 6
                        }
                    >
                        Disable
                    </AccountButton>
                </DialogActions>
            </Dialog>
        </>
    )
}