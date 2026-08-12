import { AccountCircle, Devices, Lock, Security } from "@mui/icons-material"
import {
    Avatar,
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    Stack,
    Typography,
} from "@mui/material"
import { useEffect, useState } from "react"
import { Link } from "react-router"
import { useUser } from "../../../hooks/useUser.ts"
import { Permissions, usePermissions } from "../../../hooks/usePermissions.ts"
import { accountApi } from "../../../api/account.ts"

export default function OverviewPage() {
    const user = useUser()
    const permissions = usePermissions()
    const [sessionCount, setSessionCount] = useState<number | null>(null)

    const isAdmin = permissions.hasAny([
        Permissions.ADMIN_USER_READ,
        Permissions.ADMIN_CLIENT_READ,
        Permissions.ADMIN_ROLE_READ,
        Permissions.ADMIN_AUDIT_READ,
    ])

    useEffect(() => {
        accountApi
            .sessions()
            .then(({ data }) => setSessionCount(data.length))
            .catch(() => setSessionCount(null))
    }, [])

    return (
        <Stack
            spacing={4}
            sx={{
                maxWidth: 1200,
                mx: "auto",
            }}
        >
            <Box>
                <Typography
                    variant="h4"
                    sx={{
                        fontWeight: 700,
                    }}
                >
                    Welcome back, {user.firstName || user.username}
                </Typography>

                <Typography
                    sx={{
                        mt: 1,
                        color: "text.secondary",
                    }}
                >
                    Manage your identity and account across connected services.
                </Typography>
            </Box>

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: {
                        xs: "1fr",
                        md: "repeat(3, 1fr)",
                    },
                    gap: 2,
                }}
            >
                <Card>
                    <CardContent>
                        <Stack spacing={2}>
                            <Avatar
                                sx={{
                                    bgcolor: "primary.main",
                                }}
                            >
                                <AccountCircle />
                            </Avatar>

                            <Box>
                                <Typography
                                    variant="h6"
                                    sx={{
                                        fontWeight: 600,
                                    }}
                                >
                                    Account
                                </Typography>

                                <Typography
                                    variant="body2"
                                    sx={{
                                        color: "text.secondary",
                                    }}
                                >
                                    Manage your personal information and security.
                                </Typography>
                            </Box>

                            <Chip
                                label={user.email_verified ? "Email verified" : "Email not verified"}
                                color={user.email_verified ? "success" : "warning"}
                                variant="outlined"
                                sx={{ width: "fit-content" }}
                            />

                            <Button component={Link} to="/account" variant="outlined">
                                Manage account
                            </Button>
                        </Stack>
                    </CardContent>
                </Card>

                <Card>
                    <CardContent>
                        <Stack spacing={2}>
                            <Avatar
                                sx={{
                                    bgcolor: user.mfa_enabled ? "success.main" : "warning.main",
                                }}
                            >
                                <Lock />
                            </Avatar>

                            <Box>
                                <Typography
                                    variant="h6"
                                    sx={{
                                        fontWeight: 600,
                                    }}
                                >
                                    Security
                                </Typography>

                                <Typography
                                    variant="body2"
                                    sx={{
                                        color: "text.secondary",
                                    }}
                                >
                                    {user.mfa_enabled
                                        ? "Two-factor authentication is protecting your account."
                                        : "Add two-factor authentication for stronger protection."}
                                </Typography>
                            </Box>

                            <Chip
                                label={user.mfa_enabled ? "Two-factor enabled" : "Two-factor off"}
                                color={user.mfa_enabled ? "success" : "warning"}
                                variant="outlined"
                                sx={{ width: "fit-content" }}
                            />

                            <Button component={Link} to="/account" variant="outlined">
                                Security settings
                            </Button>
                        </Stack>
                    </CardContent>
                </Card>

                <Card>
                    <CardContent>
                        <Stack spacing={2}>
                            <Avatar
                                sx={{
                                    bgcolor: "secondary.main",
                                }}
                            >
                                {isAdmin ? <Security /> : <Devices />}
                            </Avatar>

                            <Box>
                                <Typography
                                    variant="h6"
                                    sx={{
                                        fontWeight: 600,
                                    }}
                                >
                                    {isAdmin ? "Administration" : "Devices"}
                                </Typography>

                                <Typography
                                    variant="body2"
                                    sx={{
                                        color: "text.secondary",
                                    }}
                                >
                                    {isAdmin
                                        ? "Users, OAuth applications, roles and the audit trail."
                                        : sessionCount === null
                                          ? "Review the devices signed in to your account."
                                          : `${sessionCount} active session${sessionCount === 1 ? "" : "s"}.`}
                                </Typography>
                            </Box>

                            <Button
                                component={Link}
                                to={isAdmin ? "/admin" : "/account"}
                                variant="outlined"
                            >
                                {isAdmin ? "Open admin" : "Review sessions"}
                            </Button>
                        </Stack>
                    </CardContent>
                </Card>
            </Box>
        </Stack>
    )
}
