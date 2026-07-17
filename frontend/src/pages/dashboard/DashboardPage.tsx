import {
    Logout,
    Menu
} from "@mui/icons-material"
import {
    AppBar,
    Avatar,
    Box,
    Divider,
    Drawer,
    IconButton,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Stack,
    Toolbar,
    Typography,
    useMediaQuery,
    useTheme,
    Button,
} from "@mui/material"
import {useState} from "react"
import {Link, Outlet, useLocation, useNavigate} from "react-router"
import {useAuthStore} from "../../stores/auth.store"
import {useUser} from "../../hooks/useUser"
import {DashboardComponents} from "./DashboardComponents.ts"
import {useConfirm} from "../../hooks/useConfirm.ts";

const drawerWidth = 250

export default function DashboardPage() {
    const theme = useTheme()
    const isMobile = useMediaQuery(theme.breakpoints.down("md"))
    const [mobileOpen, setMobileOpen] = useState(false)
    const user = useUser()
    const logout = useAuthStore((state) => state.logout)
    const navigate = useNavigate()
    const location = useLocation()
    const {confirm} = useConfirm()

    const handleLogout = async () => {
        const confirmed = await confirm({
            title: "Logout?",
            message: "You will be signed out.",
            confirmText: "Logout",
        })

        if (!confirmed) return

        await logout()
        navigate("/login")
    }

    const drawer = (
        <Box
            sx={{
                height: "100%",
                display: "flex",
                flexDirection: "column",
            }}
        >
            {/* Header */}
            <Box
                sx={{
                    px: 3,
                    py: 3,
                }}
            >
                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700,
                        letterSpacing: "-0.03em",
                    }}
                >
                    ID Service
                </Typography>

                <Typography
                    variant="caption"
                    sx={{
                        color: "text.secondary",
                    }}
                >
                    Identity infrastructure
                </Typography>
            </Box>

            <Divider/>

            <List
                sx={{
                    px: 1.5,
                    py: 2,
                    flex: 1,
                }}
            >
                {DashboardComponents.map((component) => {
                    const Icon = component.icon

                    const selected =
                        component.path === "/"
                            ? location.pathname === component.path
                            : location.pathname.startsWith(component.path)

                    return (
                        <ListItemButton
                            key={component.path}
                            component={Link}
                            to={component.path}
                            selected={selected}
                            onClick={() => setMobileOpen(false)}
                            sx={{
                                borderRadius: 2,
                                mb: 0.5,
                                "&.Mui-selected": {
                                    backgroundColor:
                                        "rgba(88, 101, 242, 0.16)",
                                    color: "primary.light",
                                },
                            }}
                        >
                            <ListItemIcon
                                sx={{
                                    minWidth: 40,
                                    color: "inherit",
                                }}
                            >
                                <Icon/>
                            </ListItemIcon>

                            <ListItemText
                                primary={component.name}
                                slotProps={{
                                    primary: {
                                        sx: {
                                            fontWeight: 500,
                                        },
                                    },
                                }}
                            />
                        </ListItemButton>
                    )
                })}
            </List>

            <Box
                sx={{
                    borderTop: "1px solid",
                    borderColor: "divider",
                    p: 2,
                    mt: "auto",
                }}
            >
                <Stack spacing={1.5}>
                    <Stack sx={{
                        display: "flex",
                        flexDirection: "row",
                        alignItems: "center",
                        gap: 1.5,
                    }}>
                        <Avatar
                            sx={{
                                bgcolor: "primary.main",
                                width: 36,
                                height: 36,
                                fontSize: "0.9rem",
                                fontWeight: 600,
                                "&:hover": {
                                    scale: "125%"
                                },
                            }}
                        >
                            {user.firstName.charAt(0).toUpperCase()}{user.lastName.charAt(0).toUpperCase()}
                        </Avatar>

                        <Stack sx={{
                            display: "flex",
                            flexDirection: "column",
                            minWidth: 0,
                        }}>
                            <Typography
                                noWrap
                                sx={{
                                    fontWeight: 600,
                                    fontSize: "0.875rem",
                                    lineHeight: 1.3,
                                }}
                            >
                                {user.firstName} {user.lastName}
                            </Typography>

                            <Typography
                                noWrap
                                variant="caption"
                                sx={{
                                    color: "text.secondary",
                                    fontSize: "0.7rem",
                                    display: "block",
                                }}
                            >
                                {user.email}
                            </Typography>
                        </Stack>
                    </Stack>

                    <Button
                        variant="outlined"
                        color="error"
                        size="small"
                        startIcon={<Logout/>}
                        onClick={handleLogout}
                        sx={{
                            justifyContent: "flex-start",
                            borderRadius: 2,
                            textTransform: "none",
                            fontWeight: 500,
                            borderColor: "rgba(239, 68, 68, 0.3)",
                            "&:hover": {
                                borderColor: "error.main",
                                backgroundColor: "rgba(239, 68, 68, 0.08)",
                            },
                        }}
                    >
                        Logout
                    </Button>
                </Stack>
            </Box>
        </Box>
    )

    return (
        <Box
            sx={{
                display: "flex",
                minHeight: "100vh",
            }}
        >
            <AppBar
                position="fixed"
                elevation={0}
                sx={{
                    display: {
                        xs: "flex",
                        md: "none",
                    },
                    background: "rgba(11, 15, 25, 0.8)",
                    backdropFilter: "blur(16px)",
                    borderBottom: "1px solid",
                    borderColor: "divider",
                }}
            >
                <Toolbar>
                    <IconButton
                        color="inherit"
                        edge="start"
                        onClick={() => setMobileOpen(true)}
                    >
                        <Menu/>
                    </IconButton>

                    <Typography
                        sx={{
                            ml: 2,
                            fontWeight: 700,
                        }}
                    >
                        ID Service
                    </Typography>
                </Toolbar>
            </AppBar>

            <Box
                component="nav"
                sx={{
                    width: {
                        md: drawerWidth,
                    },
                    flexShrink: {
                        md: 0,
                    },
                }}
            >
                <Drawer
                    variant={isMobile ? "temporary" : "permanent"}
                    open={isMobile ? mobileOpen : true}
                    onClose={() => setMobileOpen(false)}
                    ModalProps={{
                        keepMounted: true,
                    }}
                    sx={{
                        "& .MuiDrawer-paper": {
                            boxSizing: "border-box",
                            width: drawerWidth,
                            backgroundColor: "background.paper",
                            borderRight: "1px solid",
                            borderColor: "divider",
                        },
                    }}
                >
                    {drawer}
                </Drawer>
            </Box>

            <Box
                component="main"
                sx={{
                    flexGrow: 1,
                    minWidth: 0,
                    pt: {
                        xs: 10,
                        md: 4,
                    },
                    px: {
                        xs: 2,
                        sm: 4,
                        md: 6,
                    },
                    pb: 6,
                }}
            >
                <Outlet/>
            </Box>
        </Box>
    )
}