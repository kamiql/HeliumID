import {
    AccountCircle,
    Lock,
    Settings,
} from "@mui/icons-material"
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
import { Link } from "react-router"
import {useUser} from "../../../hooks/useUser.ts";

export default function OverviewPage() {
    const user = useUser()

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
                    Welcome back, {user.firstName}
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
                                    Manage your personal information and
                                    security.
                                </Typography>
                            </Box>

                            <Button
                                component={Link}
                                to="/account"
                                variant="outlined"
                            >
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
                                    bgcolor: "success.main",
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
                                    Your account is protected by the ID Service.
                                </Typography>
                            </Box>

                            <Chip
                                label="Protected"
                                color="success"
                                variant="outlined"
                            />
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
                                <Settings />
                            </Avatar>

                            <Box>
                                <Typography
                                    variant="h6"
                                    sx={{
                                        fontWeight: 600,
                                    }}
                                >
                                    Connected services
                                </Typography>

                                <Typography
                                    variant="body2"
                                    sx={{
                                        color: "text.secondary",
                                    }}
                                >
                                    OAuth and OIDC integrations will appear here
                                    later.
                                </Typography>
                            </Box>

                            <Chip
                                label="Coming soon"
                                variant="outlined"
                            />
                        </Stack>
                    </CardContent>
                </Card>
            </Box>
        </Stack>
    )
}