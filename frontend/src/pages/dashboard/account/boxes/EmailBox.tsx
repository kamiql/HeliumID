import {
    Alert,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Link,
    Stack,
} from "@mui/material"
import { CheckCircleOutlined, ErrorOutlined } from "@mui/icons-material"
import { useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { ACCOUNT_ANCHORS } from "../../../../components/dashboard/account/AccountRequirement.tsx"
import DefinitionList from "../../../../components/ui/DefinitionList.tsx"
import EmailField from "../../../../components/EmailField.tsx"
import PasswordField from "../../../../components/PasswordField.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import VerificationDialog from "../../../../components/VerificationDialog.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { useAuthStore } from "../../../../stores/auth.store.ts"
import { accountApi } from "../../../../api/account.ts"
import { authApi } from "../../../../api/auth.ts"
import { describeFieldError, toHeliumError } from "../../../../api/problem.ts"
import { notify } from "../../../../stores/notice.store.ts"

/**
 * The email address, and the two-step change flow.
 *
 * Step one takes the new address plus the current password; step two consumes a token mailed to
 * the *new* address. Only then is the address moved. A stolen session therefore cannot quietly
 * redirect account recovery to an attacker's mailbox.
 */
export default function EmailBox() {
    const user = useUser()
    const refresh = useAuthStore((state) => state.refresh)

    const [open, setOpen] = useState(false)
    const [confirmOpen, setConfirmOpen] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<unknown>(null)
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

    const [newEmail, setNewEmail] = useState("")
    const [password, setPassword] = useState("")

    const handleClose = () => {
        if (loading) return
        setOpen(false)
        setNewEmail("")
        setPassword("")
        setError(null)
        setFieldErrors({})
    }

    const handleRequest = async () => {
        if (!newEmail || !password) return

        try {
            setLoading(true)
            setError(null)
            setFieldErrors({})

            await accountApi.requestEmailChange({
                new_email: newEmail,
                current_password: password,
            })

            setOpen(false)
            setPassword("")
            setConfirmOpen(true)
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            setFieldErrors(heliumError.fieldErrors)
            setError(heliumError)
        } finally {
            setLoading(false)
        }
    }

    const handleResendVerification = async () => {
        try {
            await authApi.resendVerification(user.email)
            notify("Verification email sent.", "success")
        } catch (caught) {
            notify(toHeliumError(caught).message, "error")
        }
    }

    return (
        <>
            <AccountBox
                id={ACCOUNT_ANCHORS.email}
                title="Email address"
                description="The address used for sign-in notices and account recovery."
                actions={
                    <AccountButton variant="contained" onClick={() => setOpen(true)}>
                        Change email
                    </AccountButton>
                }
                banner={
                    <Chip
                        size="small"
                        variant="outlined"
                        color={user.email_verified ? "success" : "warning"}
                        icon={user.email_verified ? <CheckCircleOutlined /> : <ErrorOutlined />}
                        label={user.email_verified ? "Verified" : "Not verified"}
                    />
                }
            >
                <Stack sx={{ gap: 2, alignItems: "flex-start" }}>
                    <DefinitionList
                        columns={1}
                        sx={{ width: "100%" }}
                        items={[{ label: "Current address", value: user.email, wide: true }]}
                    />

                    {!user.email_verified && (
                        <Alert
                            severity="warning"
                            sx={{ alignSelf: "stretch" }}
                            action={
                                <AccountButton
                                    color="inherit"
                                    size="small"
                                    aria-label="Resend verification email"
                                    onClick={() => void handleResendVerification()}
                                >
                                    Resend
                                </AccountButton>
                            }
                        >
                            This address is not verified yet. Open the link in the verification
                            email, or send yourself a new one.
                        </Alert>
                    )}

                    {/*
                     * The rare path: someone who has the mail open but lost the tab. It stays
                     * reachable, quietly, rather than sitting beside the primary action.
                     */}
                    <Link
                        component="button"
                        type="button"
                        variant="body2"
                        onClick={() => setConfirmOpen(true)}
                    >
                        I already have a confirmation code
                    </Link>
                </Stack>
            </AccountBox>

            <Dialog open={open} onClose={handleClose} fullWidth maxWidth="xs">
                <DialogTitle>Change email address</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <Alert severity="info">
                            We will send a confirmation link to the new address. The change only
                            takes effect once you open it.
                        </Alert>

                        <EmailField
                            required
                            fullWidth
                            autoFocus
                            label="New email address"
                            value={newEmail}
                            onType={(value) => {
                                setNewEmail(value)
                                setError(null)
                            }}
                            error={Boolean(fieldErrors.new_email)}
                            helperText={
                                fieldErrors.new_email
                                    ? describeFieldError(fieldErrors.new_email)
                                    : undefined
                            }
                        />

                        <PasswordField
                            required
                            fullWidth
                            label="Current password"
                            autoComplete="current-password"
                            value={password}
                            onType={(value) => {
                                setPassword(value)
                                setError(null)
                            }}
                            error={Boolean(fieldErrors.current_password)}
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
                        onClick={() => void handleRequest()}
                        disabled={loading || !newEmail || !password}
                    >
                        Send confirmation
                    </AccountButton>
                </DialogActions>
            </Dialog>

            <VerificationDialog
                open={confirmOpen}
                title="Confirm new email address"
                description="Paste the confirmation code from the email we sent to your new address."
                onSubmit={(token) => accountApi.confirmEmailChange(token).then(() => undefined)}
                onClose={() => setConfirmOpen(false)}
                onCompleted={() => {
                    setConfirmOpen(false)
                    setNewEmail("")
                    void refresh()
                    notify("Email address updated.", "success")
                }}
            />
        </>
    )
}
