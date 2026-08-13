import {
    Alert,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    Typography,
} from "@mui/material"
import { useState } from "react"
import { useNavigate } from "react-router"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import PasswordField from "../../../../components/PasswordField.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { useAuthStore } from "../../../../stores/auth.store.ts"
import { accountApi } from "../../../../api/account.ts"
import { notify } from "../../../../stores/notice.store.ts"

export default function DangerZoneBox() {
    const clearSession = useAuthStore((state) => state.clearSession)
    const navigate = useNavigate()

    const [open, setOpen] = useState(false)
    const [password, setPassword] = useState("")
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(false)

    const handleDelete = async () => {
        try {
            setLoading(true)
            setError(null)

            // `null` rather than an empty string: an account created through a provider has no
            // password to confirm with, and the server decides what proof it needs.
            await accountApi.deleteAccount({ current_password: password || null })

            clearSession()
            notify("Your account has been deleted.", "info")
            navigate("/login", { replace: true })
        } catch (caught) {
            setError(caught)
        } finally {
            setLoading(false)
        }
    }

    return (
        <>
            <AccountBox
                title="Delete account"
                description="Permanently delete your account and all associated data."
                tone="danger"
                actions={
                    <AccountButton
                        variant="contained"
                        color="error"
                        aria-label="Delete account"
                        onClick={() => {
                            setPassword("")
                            setError(null)
                            setOpen(true)
                        }}
                    >
                        Delete account
                    </AccountButton>
                }
            >
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    This action cannot be undone. Your profile, sessions and linked providers are
                    removed, and any application signed in through HeliumID loses access.
                </Typography>
            </AccountBox>

            <Dialog
                open={open}
                onClose={() => (loading ? undefined : setOpen(false))}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Delete account</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <Alert severity="error">
                            Your profile, sessions and linked providers will be removed. Security
                            and audit records are retained as required.
                        </Alert>

                        <PasswordField
                            fullWidth
                            autoFocus
                            label="Current password"
                            autoComplete="current-password"
                            value={password}
                            onType={(value) => {
                                setPassword(value)
                                setError(null)
                            }}
                            // Deliberately optional: an account that only ever signed in through a
                            // provider has no password, and the server is the one that decides
                            // whether the proof it was given is enough.
                            helperText="Leave empty if you only ever sign in with a linked provider and have never set a password."
                        />

                        {error !== null && <ErrorAlert error={error} />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <AccountButton onClick={() => setOpen(false)} disabled={loading}>
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        color="error"
                        onClick={() => void handleDelete()}
                        disabled={loading}
                    >
                        Delete my account
                    </AccountButton>
                </DialogActions>
            </Dialog>
        </>
    )
}
