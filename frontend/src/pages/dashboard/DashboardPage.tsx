import {
    ExpandLess,
    ExpandMore,
    Logout,
    Menu,
} from "@mui/icons-material";
import {
    AppBar,
    Avatar,
    Box,
    Collapse,
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
} from "@mui/material";
import {useState} from "react";
import {Link, Outlet, useLocation, useNavigate} from "react-router";
import {useAuthStore} from "../../stores/auth.store";
import {useUser} from "../../hooks/useUser";
import {DashboardComponents, type DashboardComponent} from "./DashboardComponents.ts";
import {useConfirm} from "../../hooks/useConfirm.ts";
import {useUserRoles} from "../../hooks/useUserRoles.ts";

const drawerWidth = 250;

export default function DashboardPage() {
    const theme = useTheme();
    const isMobile = useMediaQuery(theme.breakpoints.down("md"));
    const [mobileOpen, setMobileOpen] = useState(false);
    const [expanded, setExpanded] = useState<string[]>([]);
    const user = useUser();
    const roles = useUserRoles();
    const logout = useAuthStore((state) => state.logout);
    const navigate = useNavigate();
    const location = useLocation();
    const {confirm} = useConfirm();

    const permissions = roles.flatMap((role) => role.permissions);

    const hasPermission = (
        require: string[],
        all = false
    ) =>
        all
            ? require.every((permission) => permissions.includes(permission))
            : require.some((permission) => permissions.includes(permission));

    const canAccess = (component: DashboardComponent) =>
        !component.require ||
        hasPermission(component.require, component.all);

    const handleLogout = async () => {
        const confirmed = await confirm({
            title: "Logout?",
            message: "You will be signed out.",
            confirmText: "Logout",
        });

        if (!confirmed) return;

        await logout();
        navigate("/login");
    };

    const isSelected = (path: string) =>
        location.pathname === path;

    const hasActiveChild = (component: DashboardComponent) =>
        component.children?.some(
            (child) =>
                canAccess(child) &&
                child.path !== undefined &&
                isSelected(child.path)
        ) ?? false;

    const toggleExpanded = (name: string) => {
        setExpanded((current) =>
            current.includes(name)
                ? current.filter((item) => item !== name)
                : [...current, name]
        );
    };

    const renderComponent = (
        component: DashboardComponent,
        nested = false
    ): React.ReactNode => {
        if (!canAccess(component)) return null;

        const Icon = component.icon;
        const children = component.children?.filter(canAccess);
        const hasChildren = Boolean(children?.length);
        const selected = component.path
            ? isSelected(component.path)
            : hasActiveChild(component);
        const isExpanded =
            expanded.includes(component.name) || hasActiveChild(component);

        if (hasChildren) {
            return (
                <Box key={component.name}>
                    <ListItemButton
                        selected={selected}
                        onClick={() => toggleExpanded(component.name)}
                        sx={{
                            borderRadius: 2,
                            mb: 0.5,
                            pl: nested ? 4 : 2,
                            "&.Mui-selected": {
                                backgroundColor: "rgba(88, 101, 242, 0.16)",
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

                        <ListItemText primary={component.name}/>

                        {isExpanded ? <ExpandLess/> : <ExpandMore/>}
                    </ListItemButton>

                    <Collapse in={isExpanded} timeout="auto" unmountOnExit>
                        <List disablePadding>
                            {children?.map((child) =>
                                renderComponent(child, true)
                            )}
                        </List>
                    </Collapse>
                </Box>
            );
        }

        if (!component.path) return null;

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
                    pl: nested ? 4 : 2,
                    "&.Mui-selected": {
                        backgroundColor: "rgba(88, 101, 242, 0.16)",
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

                <ListItemText primary={component.name}/>
            </ListItemButton>
        );
    };

    const drawer = (
        <Box
            sx={{
                height: "100%",
                display: "flex",
                flexDirection: "column",
            }}
        >
            <Box sx={{px: 3, py: 3}}>
                <Typography variant="h4" sx={{fontFamily: "Silkscreen, sans-serif",}}>
                    HeliumID
                </Typography>
            </Box>

            <Divider/>

            <List sx={{px: 1.5, py: 2, flex: 1}}>
                {DashboardComponents.map((component) =>
                    renderComponent(component)
                )}
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
                    <Stack
                        sx={{
                            display: "flex",
                            flexDirection: "row",
                            alignItems: "center",
                            gap: 1.5,
                        }}
                    >
                        <Avatar
                            sx={{
                                bgcolor: "primary.main",
                                width: 36,
                                height: 36,
                                fontSize: "0.9rem",
                                fontWeight: 600,
                            }}
                        >
                            {user.firstName.charAt(0).toUpperCase()}
                            {user.lastName.charAt(0).toUpperCase()}
                        </Avatar>

                        <Stack sx={{minWidth: 0}}>
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
                        }}
                    >
                        Logout
                    </Button>
                </Stack>
            </Box>
        </Box>
    );

    return (
        <Box sx={{display: "flex", minHeight: "100vh"}}>
            <AppBar
                position="fixed"
                elevation={0}
                sx={{
                    display: {
                        xs: "flex",
                        md: "none",
                    },
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

                    <Typography sx={{ml: 2, fontWeight: 700}}>
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
    );
}