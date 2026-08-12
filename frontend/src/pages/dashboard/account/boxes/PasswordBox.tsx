import {
    Alert,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
} from "@mui/material"
import { useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import PasswordField from "../../../../components/PasswordField.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { accountApi } from "../../../../api/account.ts"
import { describeFieldError, toHeliumError } from "../../../../api/problem.ts"
import { evaluatePassword, usePasswordRequirements } from "../../../../hooks/usePasswordRequirements.ts"
import { notify } from "../../../../stores/notice.store.ts"

export default function PasswordBox() {
    const user = useUser()
    const requirements = usePasswordRequirements()

    const [open, setOpen] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<unknown>(null)
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

    const [currentPassword, setCurrentPassword] = useState("")
    const [newPassword, setNewPassword] = useState("")
    const [confirm, setConfirm] = useState("")

    const checks = evaluatePassword(requirements, newPassword, [user.username, user.email])
    const policyMet = checks.every((check) => check.satisfied !== false)

    const reset = () => {
        setCurrentPassword("")
        setNewPassword("")
        setConfirm("")
        setError(null)
        setFieldErrors({})
    }

    const handleClose = () => {
        if (loading) return
        setOpen(false)
        reset()
    }

    const handleChange = async () => {
        if (!currentPassword || !newPassword || newPassword !== confirm) return

        try {
            setLoading(true)
            setError(null)
            setFieldErrors({})

            await accountApi.changePassword({
                current_password: currentPassword,
                new_password: newPassword,
            })

            setOpen(false)
            reset()
            // The server revokes the other sessions as part of the change; this one survives.
            notify("Password changed. Other sessions were signed out.", "success")
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            setFieldErrors(heliumError.fieldErrors)
            setError(heliumError)
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
                        satisfied: user.email_verified,
                    },
                ]}
                sx={{
                    flex: "1 1 300px",
                    minWidth: "250px",
                }}
            >
                <AccountButton
                    variant="outlined"
                    onClick={() => {
                        reset()
                        setOpen(true)
                    }}
                >
                    Change password
                </AccountButton>
            </AccountBox>

            <Dialog open={open} onClose={handleClose} fullWidth maxWidth="xs">
                <DialogTitle>Change password</DialogTitle>

                <DialogContent>
                    <Stack spacing={1}>
                        <Alert severity="warning">
                            Every other signed-in device will be signed out.
                        </Alert>

                        <PasswordField
                            margin="normal"
                            required
                            fullWidth
                            label="Current password"
                            autoComplete="current-password"
                            autoFocus
                            value={currentPassword}
                            onType={(value) => {
                                setCurrentPassword(value)
                                setError(null)
                            }}
                            error={Boolean(fieldErrors.current_password)}
                            helperText={
                                fieldErrors.current_password
                                    ? describeFieldError(fieldErrors.current_password)
                                    : undefined
                            }
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
                                setError(null)
                            }}
                            validate
                            identifiers={[user.username, user.email]}
                            error={Boolean(fieldErrors.new_password)}
                        />

                        {fieldErrors.new_password && (
                            <Alert severity="error">
                                {describeFieldError(fieldErrors.new_password)}
                            </Alert>
                        )}

                        <PasswordField
                            margin="normal"
                            required
                            fullWidth
                            label="Confirm new password"
                            autoComplete="new-password"
                            value={confirm}
                            onType={(value) => {
                                setConfirm(value)
                                setError(null)
                            }}
                            matches={newPassword}
                            validate
                        />

                        {error !== null && <ErrorAlert error={error} hideFieldErrors />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <AccountButton onClick={handleClose} disabled={loading}>
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        onClick={() => void handleChange()}
                        disabled={
                            loading ||
                            !currentPassword ||
                            !newPassword ||
                            newPassword !== confirm ||
                            !policyMet
                        }
                    >
                        Change password
                    </AccountButton>
                </DialogActions>
            </Dialog>
        </>
    )
}
