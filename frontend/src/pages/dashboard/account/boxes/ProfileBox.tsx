import {
    Box,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    TextField,
    Typography,
} from "@mui/material"
import { useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { useAuthStore } from "../../../../stores/auth.store.ts"
import { accountApi } from "../../../../api/account.ts"
import { describeFieldError, toHeliumError } from "../../../../api/problem.ts"
import { notify } from "../../../../stores/notice.store.ts"

/** Username and name. The email address has its own box — changing it is a two-step flow. */
export default function ProfileBox() {
    const user = useUser()
    const setUser = useAuthStore((state) => state.setUser)

    const [open, setOpen] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<unknown>(null)
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

    const [username, setUsername] = useState(user.username)
    const [firstName, setFirstName] = useState(user.firstName)
    const [lastName, setLastName] = useState(user.lastName)

    const handleOpen = () => {
        setUsername(user.username)
        setFirstName(user.firstName)
        setLastName(user.lastName)
        setError(null)
        setFieldErrors({})
        setOpen(true)
    }

    const handleClose = () => {
        if (loading) return
        setOpen(false)
    }

    const handleSave = async () => {
        try {
            setLoading(true)
            setError(null)
            setFieldErrors({})

            const { data } = await accountApi.updateProfile({ username, firstName, lastName })
            setUser(data)
            setOpen(false)
            notify("Profile updated.", "success")
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            setFieldErrors(heliumError.fieldErrors)
            setError(heliumError)
        } finally {
            setLoading(false)
        }
    }

    const fields: [string, string][] = [
        ["Username", user.username],
        ["First name", user.firstName || "—"],
        ["Last name", user.lastName || "—"],
        ["Member since", new Date(user.created_at).toLocaleDateString()],
    ]

    return (
        <>
            <AccountBox
                title="Personal information"
                description="Information associated with your identity."
                sx={{
                    flex: "1 1 300px",
                    minWidth: "250px",
                }}
            >
                <Box
                    sx={{
                        display: "grid",
                        gridTemplateColumns: {
                            xs: "1fr",
                            sm: "1fr 1fr",
                        },
                        gap: 3,
                    }}
                >
                    {fields.map(([label, value]) => (
                        <Box key={label}>
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                {label}
                            </Typography>

                            <Typography sx={{ mt: 0.5 }}>{value}</Typography>
                        </Box>
                    ))}
                </Box>

                <AccountButton variant="contained" onClick={handleOpen}>
                    Edit personal information
                </AccountButton>
            </AccountBox>

            <Dialog open={open} onClose={handleClose} fullWidth maxWidth="xs">
                <DialogTitle>Edit personal information</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <TextField
                            required
                            fullWidth
                            label="Username"
                            value={username}
                            onChange={(event) => setUsername(event.target.value)}
                            error={Boolean(fieldErrors.username)}
                            helperText={
                                fieldErrors.username
                                    ? describeFieldError(fieldErrors.username)
                                    : undefined
                            }
                        />

                        <TextField
                            fullWidth
                            label="First name"
                            value={firstName}
                            onChange={(event) => setFirstName(event.target.value)}
                        />

                        <TextField
                            fullWidth
                            label="Last name"
                            value={lastName}
                            onChange={(event) => setLastName(event.target.value)}
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
                        onClick={() => void handleSave()}
                        disabled={loading || username.trim().length === 0}
                    >
                        Save changes
                    </AccountButton>
                </DialogActions>
            </Dialog>
        </>
    )
}
