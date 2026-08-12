import {
    Alert,
    Box,
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
                title="Danger zone"
                description="Permanently delete your account and all associated data."
                sx={{
                    flex: "1 1 100%",
                    border: "1px solid",
                    borderColor: "error.main",
                }}
            >
                <Box
                    sx={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        gap: 2,
                        flexWrap: "wrap",
                    }}
                >
                    <Typography variant="body2">This action cannot be undone.</Typography>

                    <AccountButton
                        variant="contained"
                        color="error"
                        onClick={() => {
                            setPassword("")
                            setError(null)
                            setOpen(true)
                        }}
                    >
                        Delete account
                    </AccountButton>
                </Box>
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

                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Confirm with your password to continue.
                        </Typography>

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
