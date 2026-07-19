import {
    Alert,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    Typography,
} from "@mui/material"
import {useState} from "react"
import axios from "axios"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx";
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx";
import {userApi} from "../../../../api/user.ts"
import PasswordField from "../../../../components/PasswordField.tsx"
import {useUser} from "../../../../hooks/useUser.ts"

export default function PasswordBox() {
    const user = useUser()

    const [open, setOpen] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState("")

    const [oldPassword, setOldPassword] = useState("")
    const [newPassword, setNewPassword] = useState("")
    const [passwordConfirm, setPasswordConfirm] = useState("")

    const handleOpen = () => {
        setError("")
        setOldPassword("")
        setNewPassword("")
        setPasswordConfirm("")
        setOpen(true)
    }

    const handleClose = () => {
        if (loading) return

        setOpen(false)
        setError("")
        setOldPassword("")
        setNewPassword("")
        setPasswordConfirm("")
    }

    const handleChange = async () => {
        if (!oldPassword || !newPassword || !passwordConfirm) {
            setError("Please fill out all fields")
            return
        }

        if (newPassword !== passwordConfirm) {
            setError("Passwords do not match")
            return
        }

        try {
            setLoading(true)
            setError("")

            await userApi.changePassword({
                old: oldPassword,
                new: newPassword,
            })

            handleClose()
            window.location.reload()
        } catch (error) {
            if (
                axios.isAxiosError(error) &&
                error.response?.status === 401
            ) {
                setError(
                    error.response?.data?.message ||
                    error.response?.data ||
                    "Failed to change password",
                )
                return
            }

            setError("Failed to change password")
        } finally {
            setLoading(false)
        }
    }

    return (
        <>
            <AccountBox
                title="Password"
                description="Change the password used to access your identity."
                requirements={[
                    {
                        id: "email",
                        label: "Email verification required",
                        satisfied: user.emailVerified,
                    },
                ]}
                sx={{
                    flex: "1 1 300px",
                    minWidth: "250px",
                }}
            >
                <AccountButton
                    variant="outlined"
                    onClick={handleOpen}
                >
                    Change password
                </AccountButton>
            </AccountBox>

            <Dialog
                open={open}
                onClose={handleClose}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Change password</DialogTitle>

                <DialogContent>
                    <Stack spacing={1}>
                        <Alert severity="warning">
                            You will be logged out after changing your password.
                        </Alert>

                        <PasswordField
                            margin="normal"
                            required
                            fullWidth
                            label="Current password"
                            autoComplete="current-password"
                            autoFocus
                            value={oldPassword}
                            onType={(value) => {
                                setOldPassword(value)
                                setError("")
                            }}
                        />

                        <PasswordField
                            margin="normal"
                            required
                            fullWidth
                            label="New password"
                            autoComplete="new-password"
                            value={newPassword}
                            onType={(value) => {
                                setNewPassword(value)
                                setError("")
                            }}
                            validate
                        />

                        <PasswordField
                            margin="normal"
                            required
                            fullWidth
                            label="Confirm new password"
                            autoComplete="new-password"
                            value={passwordConfirm}
                            onType={(value) => {
                                setPasswordConfirm(value)
                                setError("")
                            }}
                            matches={newPassword}
                            validate
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
                        onClick={handleClose}
                        disabled={loading}
                    >
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        onClick={handleChange}
                        disabled={loading}
                    >
                        Change password
                    </AccountButton>
                </DialogActions>
            </Dialog>
        </>
    )
}