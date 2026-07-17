import {
    Alert,
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Divider,
    Stack,
    TextField,
    Typography,
} from "@mui/material"
import CheckCircleIcon from "@mui/icons-material/CheckCircle"
import {useCallback, useState} from "react"
import {useAuthStore} from "../../../stores/auth.store.ts"
import {useUser} from "../../../hooks/useUser.ts"
import {userApi} from "../../../api/user.ts"
import VerificationDialog from "../../../components/VerificationDialog.tsx"
import PasswordField from "../../../components/PasswordField.tsx"
import axios from "axios"
import {DiscordIcon, GoogleIcon} from "../../../components/global/Icons.tsx"
import {authApi} from "../../../api/auth.ts"
import {useConfirm} from "../../../hooks/useConfirm.ts";
import EmailField from "../../../components/EmailField.tsx";

const PROVIDERS = [
    {id: "google", name: "Google", icon: GoogleIcon},
    {id: "discord", name: "Discord", icon: DiscordIcon}
] as const

export default function AccountPage() {
    const user = useUser()
    const initialize = useAuthStore((state) => state.initialize)
    const {confirm} = useConfirm()

    const [verificationId, setVerificationId] = useState<string | null>(null)
    const [verificationOpen, setVerificationOpen] = useState(false)
    const [verificationLoading, setVerificationLoading] = useState(false)

    const [passwordOpen, setPasswordOpen] = useState(false)
    const [passwordLoading, setPasswordLoading] = useState(false)
    const [passwordError, setPasswordError] = useState("")

    const [oldPassword, setOldPassword] = useState("")
    const [newPassword, setNewPassword] = useState("")
    const [passwordConfirm, setPasswordConfirm] = useState("")

    const [personalOpen, setPersonalOpen] = useState(false)
    const [personalLoading, setPersonalLoading] = useState(false)
    const [personalError, setPersonalError] = useState("")

    const [username, setUsername] = useState("")
    const [firstName, setFirstName] = useState("")
    const [lastName, setLastName] = useState("")
    const [email, setEmail] = useState("")

    const handleRemoveOAuthProvider = async (provider: string) => {
        const confirmed = await confirm({
            title: "Remove?",
            message: "This cannot be undone.",
            confirmText: "Remove"
        })

        if (!confirmed) return

        await userApi.removeOauthProvider(provider)
        await initialize()
    }

    const handleVerificationCompleted = useCallback(async () => {
        await initialize()

        setVerificationOpen(false)
        setVerificationId(null)
        setVerificationLoading(false)
    }, [initialize])

    const handleVerifyEmail = async () => {
        setVerificationLoading(true)

        try {
            const response = await userApi.verifyEmail()

            setVerificationId(response.data)
            setVerificationOpen(true)
        } catch {
            setVerificationLoading(false)
        }
    }

    const handleCloseVerification = () => {
        setVerificationOpen(false)
        setVerificationId(null)
        setVerificationLoading(false)
    }

    const handleOpenPassword = () => {
        setPasswordError("")
        setOldPassword("")
        setNewPassword("")
        setPasswordConfirm("")
        setPasswordOpen(true)
    }

    const handleClosePassword = () => {
        if (passwordLoading) return

        setPasswordOpen(false)
        setPasswordError("")
        setOldPassword("")
        setNewPassword("")
        setPasswordConfirm("")
    }

    const handleChangePassword = async () => {
        if (!oldPassword || !newPassword || !passwordConfirm) {
            setPasswordError("Please fill out all fields")
            return
        }

        if (newPassword !== passwordConfirm) {
            setPasswordError("Passwords do not match")
            return
        }

        try {
            setPasswordLoading(true)
            setPasswordError("")

            await userApi.changePassword({
                old: oldPassword,
                new: newPassword,
            })

            handleClosePassword()

            window.location.reload()
        } catch (error) {
            if (
                axios.isAxiosError(error) &&
                error.response?.status === 401
            ) {
                setPasswordError(
                    error.response?.data?.message ||
                    error.response?.data ||
                    "Failed to change password"
                )
                return
            }

            setPasswordError("Failed to change password")
        } finally {
            setPasswordLoading(false)
        }
    }

    const handleOpenPersonal = () => {
        setUsername(user.username)
        setFirstName(user.firstName)
        setLastName(user.lastName)
        setEmail(user.email)
        setPersonalError("")
        setPersonalOpen(true)
    }

    const handleClosePersonal = () => {
        if (personalLoading) return

        setPersonalOpen(false)
        setPersonalError("")
    }

    const handleEditPersonal = async () => {
        if (!username || !firstName || !lastName || !email) {
            setPersonalError("Please fill out all fields")
            return
        }

        try {
            setPersonalLoading(true)
            setPersonalError("")

            const response = await userApi.editPersonalInformation({
                username,
                firstName,
                lastName,
                email,
            })

            setPersonalOpen(false)

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
                setPersonalError(error.response.data)
                return
            }

            setPersonalError("Failed to update personal information")
        } finally {
            setPersonalLoading(false)
        }
    }

    const linkedAccounts = user.linkedAccounts

    return (
        <>
            <Box
                sx={{
                    maxWidth: 900,
                    mx: "auto",
                }}
            >
                {!user.emailVerified && (
                    <Alert
                        severity="warning"
                        sx={{
                            mb: 2
                        }}
                    >
                        Your email is not verified yet, some actions may not be available
                    </Alert>
                )}

                <Box sx={{mb: 4}}>
                    <Typography
                        variant="h4"
                        sx={{
                            fontWeight: 700,
                        }}
                    >
                        Account
                    </Typography>

                    <Typography
                        sx={{
                            mt: 1,
                            color: "text.secondary",
                        }}
                    >
                        Manage your personal information and account security.
                    </Typography>
                </Box>

                <Box
                    sx={{
                        display: "flex",
                        flexWrap: "wrap",
                        gap: 3,
                    }}
                >
                    <Card
                        sx={{
                            flex: "1 1 300px",
                            minWidth: "250px",
                        }}
                    >
                        <CardContent>
                            <Stack spacing={3}>
                                <Box>
                                    <Typography
                                        variant="h6"
                                        sx={{
                                            fontWeight: 600,
                                        }}
                                    >
                                        Personal information
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            mt: 0.5,
                                            color: "text.secondary",
                                        }}
                                    >
                                        Information associated with your identity.
                                    </Typography>
                                </Box>

                                <Divider/>

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

                                <Button
                                    variant="contained"
                                    onClick={handleOpenPersonal}
                                >
                                    Edit personal information
                                </Button>
                            </Stack>
                        </CardContent>
                    </Card>

                    <Card
                        sx={{
                            flex: "1 1 300px",
                            minWidth: "250px",
                        }}
                    >
                        <CardContent>
                            <Stack spacing={3}>
                                <Box>
                                    <Typography
                                        variant="h6"
                                        sx={{
                                            fontWeight: 600,
                                        }}
                                    >
                                        Password
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            mt: 0.5,
                                            color: "text.secondary",
                                        }}
                                    >
                                        Change the password used to access your
                                        identity.
                                    </Typography>
                                </Box>

                                <Divider/>

                                <Button
                                    variant="outlined"
                                    onClick={handleOpenPassword}
                                    disabled={!user.emailVerified}
                                >
                                    Change password
                                </Button>
                            </Stack>
                        </CardContent>
                    </Card>

                    <Card
                        sx={{
                            flex: "1 1 300px",
                            minWidth: "30%",
                        }}
                    >
                        <CardContent>
                            <Stack spacing={3}>
                                <Box>
                                    <Typography
                                        variant="h6"
                                        sx={{
                                            fontWeight: 600,
                                        }}
                                    >
                                        Email verification
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            mt: 0.5,
                                            color: "text.secondary",
                                        }}
                                    >
                                        Verify your email address to secure your
                                        account.
                                    </Typography>
                                </Box>

                                <Divider/>

                                <Chip
                                    label={
                                        user.emailVerified
                                            ? "Email verified"
                                            : "Email not verified"
                                    }
                                    color={
                                        user.emailVerified
                                            ? "success"
                                            : "warning"
                                    }
                                    variant="outlined"
                                    sx={{
                                        width: "fit-content",
                                    }}
                                />

                                <Button
                                    variant="outlined"
                                    disabled={
                                        user.emailVerified ||
                                        verificationLoading
                                    }
                                    onClick={handleVerifyEmail}
                                >
                                    Verify email
                                </Button>
                            </Stack>
                        </CardContent>
                    </Card>

                    <Card
                        sx={{
                            flex: "1 1 300px",
                            minWidth: "60%",
                        }}
                    >
                        <CardContent>
                            <Stack spacing={2}>
                                <Box>
                                    <Typography
                                        variant="h6"
                                        sx={{
                                            fontWeight: 600,
                                        }}
                                    >
                                        Connected Accounts
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            mt: 0.5,
                                            color: "text.secondary",
                                        }}
                                    >
                                        Link your social accounts for seamless sign-in.
                                    </Typography>
                                </Box>

                                <Divider/>

                                <Stack spacing={2}>
                                    {PROVIDERS.map((provider) => {
                                        const account =
                                            linkedAccounts[provider.id.toUpperCase()]
                                        const Icon = provider.icon

                                        return (
                                            <Box
                                                key={provider.id}
                                                sx={{
                                                    display: "flex",
                                                    alignItems: "center",
                                                    justifyContent: "space-between",
                                                    gap: 2,
                                                }}
                                            >
                                                <Box
                                                    sx={{
                                                        display: "flex",
                                                        alignItems: "center",
                                                        gap: 1.5,
                                                        minWidth: 0,
                                                    }}
                                                >
                                                    <Icon/>

                                                    <Box sx={{minWidth: 0}}>
                                                        <Typography
                                                            sx={{
                                                                fontWeight: 500,
                                                            }}
                                                        >
                                                            {provider.name}
                                                        </Typography>

                                                        {account && (
                                                            <Typography
                                                                variant="body2"
                                                                sx={{
                                                                    color: "text.secondary",
                                                                    overflow: "hidden",
                                                                    textOverflow: "ellipsis",
                                                                    whiteSpace: "nowrap",
                                                                }}
                                                            >
                                                                {account.username}
                                                                {account.email && ` · ${account.email}`}
                                                            </Typography>
                                                        )}
                                                    </Box>
                                                </Box>

                                                {account ? (
                                                    <Box
                                                        sx={{
                                                            display: "flex",
                                                            alignItems: "center",
                                                            gap: 1,
                                                            flexShrink: 0,
                                                        }}
                                                    >
                                                        <Chip
                                                            label="Linked"
                                                            color="success"
                                                            size="small"
                                                            icon={<CheckCircleIcon/>}
                                                        />

                                                        <Button
                                                            variant="contained"
                                                            size="small"
                                                            color="error"
                                                            onClick={() =>
                                                                handleRemoveOAuthProvider(
                                                                    provider.id
                                                                )
                                                            }
                                                        >
                                                            Remove
                                                        </Button>
                                                    </Box>
                                                ) : (
                                                    <Button
                                                        variant="outlined"
                                                        size="small"
                                                        onClick={() =>
                                                            authApi.oauth(provider.id)
                                                        }
                                                    >
                                                        Link
                                                    </Button>
                                                )}
                                            </Box>
                                        )
                                    })}
                                </Stack>
                            </Stack>
                        </CardContent>
                    </Card>
                </Box>
            </Box>

            <Dialog
                open={personalOpen}
                onClose={handleClosePersonal}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Edit personal information</DialogTitle>

                <DialogContent>
                    <Stack spacing={2}>
                        <Divider/>

                        <TextField
                            margin="normal"
                            required
                            fullWidth
                            label="Username"
                            value={username}
                            onChange={(event) => {
                                setUsername(event.target.value)
                                setPersonalError("")
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
                                setPersonalError("")
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
                                setPersonalError("")
                            }}
                        />

                        <EmailField
                            margin="normal"
                            required
                            fullWidth
                            label="Email"
                            value={email}
                            onType={text => setEmail(text)}
                        />

                        {email !== user.email && (
                            <Alert severity="warning">
                                Changing your email address requires email
                                verification.
                            </Alert>
                        )}

                        {personalError && (
                            <Typography
                                color="error"
                                variant="body2"
                                sx={{mt: 1}}
                            >
                                {personalError}
                            </Typography>
                        )}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <Button
                        onClick={handleClosePersonal}
                        disabled={personalLoading}
                    >
                        Cancel
                    </Button>

                    <Button
                        variant="contained"
                        onClick={handleEditPersonal}
                        disabled={personalLoading}
                    >
                        Save changes
                    </Button>
                </DialogActions>
            </Dialog>

            <Dialog
                open={passwordOpen}
                onClose={handleClosePassword}
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
                                setPasswordError("")
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
                                setPasswordError("")
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
                                setPasswordError("")
                            }}
                            matches={newPassword}
                            validate
                        />

                        {passwordError && (
                            <Typography
                                color="error"
                                variant="body2"
                                sx={{mt: 1}}
                            >
                                {passwordError}
                            </Typography>
                        )}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <Button
                        onClick={handleClosePassword}
                        disabled={passwordLoading}
                    >
                        Cancel
                    </Button>

                    <Button
                        variant="contained"
                        onClick={handleChangePassword}
                        disabled={passwordLoading}
                    >
                        Change password
                    </Button>
                </DialogActions>
            </Dialog>

            <VerificationDialog
                key={verificationId}
                open={verificationOpen}
                verificationId={verificationId}
                onClose={handleCloseVerification}
                onCompleted={handleVerificationCompleted}
            />
        </>
    )
}