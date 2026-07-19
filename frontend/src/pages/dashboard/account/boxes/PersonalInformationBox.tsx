import {
    Alert,
    Box,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    TextField,
    Typography,
} from "@mui/material"
import {useState} from "react"
import axios from "axios"
import {useAuthStore} from "../../../../stores/auth.store.ts"
import {useUser} from "../../../../hooks/useUser.ts"
import {userApi} from "../../../../api/user.ts"
import VerificationDialog from "../../../../components/VerificationDialog.tsx"
import EmailField from "../../../../components/EmailField.tsx"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx";
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx";

export default function PersonalInformationBox() {
    const user = useUser()
    const initialize = useAuthStore((state) => state.initialize)

    const [open, setOpen] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState("")

    const [verificationId, setVerificationId] = useState<string | null>(null)
    const [verificationOpen, setVerificationOpen] = useState(false)

    const [username, setUsername] = useState("")
    const [firstName, setFirstName] = useState("")
    const [lastName, setLastName] = useState("")
    const [email, setEmail] = useState("")

    const handleOpen = () => {
        setUsername(user.username)
        setFirstName(user.firstName)
        setLastName(user.lastName)
        setEmail(user.email)
        setError("")
        setOpen(true)
    }

    const handleClose = () => {
        if (loading) return

        setOpen(false)
        setError("")
    }

    const handleEdit = async () => {
        if (!username || !firstName || !lastName || !email) {
            setError("Please fill out all fields")
            return
        }

        try {
            setLoading(true)
            setError("")

            const response = await userApi.editPersonalInformation({
                username,
                firstName,
                lastName,
                email,
            })

            setOpen(false)

            if (response.data) {
                setVerificationId(response.data)
                setVerificationOpen(true)
            } else {
                await initialize()
            }
        } catch (error) {
            if (
                axios.isAxiosError(error) &&
                error.response?.status === 409
            ) {
                setError(error.response.data)
                return
            }

            setError("Failed to update personal information")
        } finally {
            setLoading(false)
        }
    }

    const handleVerificationCompleted = async () => {
        await initialize()

        setVerificationOpen(false)
        setVerificationId(null)
    }

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
                    <Box>
                        <Typography
                            variant="caption"
                            sx={{
                                color: "text.secondary",
                            }}
                        >
                            Username
                        </Typography>

                        <Typography sx={{mt: 0.5}}>
                            {user.username}
                        </Typography>
                    </Box>

                    <Box>
                        <Typography
                            variant="caption"
                            sx={{
                                color: "text.secondary",
                            }}
                        >
                            Email
                        </Typography>

                        <Typography sx={{mt: 0.5}}>
                            {user.email}
                        </Typography>
                    </Box>

                    <Box>
                        <Typography
                            variant="caption"
                            sx={{
                                color: "text.secondary",
                            }}
                        >
                            First name
                        </Typography>

                        <Typography sx={{mt: 0.5}}>
                            {user.firstName}
                        </Typography>
                    </Box>

                    <Box>
                        <Typography
                            variant="caption"
                            sx={{
                                color: "text.secondary",
                            }}
                        >
                            Last name
                        </Typography>

                        <Typography sx={{mt: 0.5}}>
                            {user.lastName}
                        </Typography>
                    </Box>
                </Box>

                <AccountButton
                    variant="contained"
                    onClick={handleOpen}
                >
                    Edit personal information
                </AccountButton>
            </AccountBox>

            <Dialog
                open={open}
                onClose={handleClose}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Edit personal information</DialogTitle>

                <DialogContent>
                    <Stack spacing={2}>
                        <TextField
                            margin="normal"
                            required
                            fullWidth
                            label="Username"
                            value={username}
                            onChange={(event) => {
                                setUsername(event.target.value)
                                setError("")
                            }}
                        />

                        <TextField
                            margin="normal"
                            required
                            fullWidth
                            label="First name"
                            value={firstName}
                            onChange={(event) => {
                                setFirstName(event.target.value)
                                setError("")
                            }}
                        />

                        <TextField
                            margin="normal"
                            required
                            fullWidth
                            label="Last name"
                            value={lastName}
                            onChange={(event) => {
                                setLastName(event.target.value)
                                setError("")
                            }}
                        />

                        <EmailField
                            margin="normal"
                            required
                            fullWidth
                            label="Email"
                            value={email}
                            onType={(text) => setEmail(text)}
                        />

                        {email !== user.email && (
                            <Alert severity="warning">
                                Changing your email address requires email verification.
                            </Alert>
                        )}

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
                        onClick={handleEdit}
                        disabled={loading}
                    >
                        Save changes
                    </AccountButton>
                </DialogActions>
            </Dialog>

            <VerificationDialog
                open={verificationOpen}
                verificationId={verificationId}
                onClose={() => {
                    setVerificationOpen(false)
                    setVerificationId(null)
                }}
                onCompleted={handleVerificationCompleted}
            />
        </>
    )
}