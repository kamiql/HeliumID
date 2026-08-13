import { ExpandLess, ExpandMore, Logout, ManageAccounts, Menu as MenuIcon } from "@mui/icons-material"
import {
    AppBar,
    Avatar,
    Box,
    ButtonBase,
    Collapse,
    Divider,
    Drawer,
    IconButton,
    Link as MuiLink,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Menu,
    MenuItem,
    Stack,
    Toolbar,
    Tooltip,
    Typography,
    useMediaQuery,
    useTheme,
} from "@mui/material"
import { useState, type ReactNode } from "react"
import { Link, Outlet, useLocation, useNavigate } from "react-router"
import { useAuthStore } from "../../stores/auth.store"
import { useUser } from "../../hooks/useUser"
import { DashboardComponents, type DashboardComponent } from "./DashboardComponents.ts"
import { useConfirm } from "../../hooks/useConfirm.ts"
import { usePermissions } from "../../hooks/usePermissions.ts"
import { NAV_WIDTH } from "../../lib/theme.ts"
import Brand from "../../components/global/Brand.tsx"
import ThemeToggle from "../../components/global/ThemeToggle.tsx"

const MAIN_CONTENT_ID = "dashboard-main"

export default function DashboardPage() {
    const theme = useTheme()
    const isMobile = useMediaQuery(theme.breakpoints.down("md"))
    const [mobileOpen, setMobileOpen] = useState(false)
    const [expanded, setExpanded] = useState<string[]>([])
    const [userMenu, setUserMenu] = useState<HTMLElement | null>(null)
    const user = useUser()
    const permissions = usePermissions()
    const logout = useAuthStore((state) => state.logout)
    const navigate = useNavigate()
    const location = useLocation()
    const { confirm } = useConfirm()

    // Effective permissions come flattened on the session payload; the drawer only hides
    // entries, every endpoint behind them re-checks the same permission server-side.
    const hasPermission = (require: string[], all = false) =>
        all ? permissions.hasAll(require) : permissions.hasAny(require)

    const canAccess = (component: DashboardComponent) =>
        !component.require || hasPermission(component.require, component.all)

    const handleLogout = async () => {
        setUserMenu(null)

        const confirmed = await confirm({
            title: "Sign out?",
            message: "You will be signed out of HeliumID on this device.",
            confirmText: "Sign out",
            tone: "default",
        })

        if (!confirmed) return

        await logout()
        navigate("/login")
    }

    // Nested routes such as /admin/users/:id keep their parent entry highlighted.
    const matchesPath = (path: string) =>
        location.pathname === path ||
        (path !== "/" && location.pathname.startsWith(`${path}/`))

    const navPaths = (components: DashboardComponent[]): string[] =>
        components.flatMap((component) => {
            if (!canAccess(component)) return []
            return component.children ? navPaths(component.children) : [component.path]
        })

    // On /admin/users the prefix rule matches both /admin/users and the section index
    // /admin, which left "Overview" highlighted alongside the entry the user actually
    // opened. Only the most specific match counts as the current page.
    const activePath = navPaths(DashboardComponents)
        .filter(matchesPath)
        .reduce<string | undefined>(
            (best, path) => (best === undefined || path.length > best.length ? path : best),
            undefined,
        )

    const isSelected = (path: string) => path === activePath

    const hasActiveChild = (component: DashboardComponent) =>
        component.children?.some(
            (child) => canAccess(child) && child.path !== undefined && isSelected(child.path),
        ) ?? false

    // First and last name are optional on the wire, so fall back to the username.
    const displayName =
        [user.firstName, user.lastName].filter(Boolean).join(" ") || user.username
    const initials =
        [user.firstName, user.lastName]
            .filter(Boolean)
            .map((part) => part.charAt(0).toUpperCase())
            .join("") || user.username.charAt(0).toUpperCase()

    const toggleExpanded = (name: string) =>
        setExpanded((current) =>
            current.includes(name)
                ? current.filter((item) => item !== name)
                : [...current, name],
        )

    const renderComponent = (component: DashboardComponent, nested = false): ReactNode => {
        if (!canAccess(component)) return null

        const Icon = component.icon
        const children = component.children?.filter(canAccess)
        const hasChildren = Boolean(children?.length)
        const selected = component.path ? isSelected(component.path) : hasActiveChild(component)
        const isExpanded = expanded.includes(component.name) || hasActiveChild(component)

        if (hasChildren) {
            return (
                <Box component="li" key={component.name} sx={{ listStyle: "none" }}>
                    <ListItemButton
                        selected={selected}
                        onClick={() => toggleExpanded(component.name)}
                        aria-expanded={isExpanded}
                        sx={{ mb: 0.25, pl: nested ? 4 : 1.5 }}
                    >
                        <ListItemIcon>
                            <Icon fontSize="small" />
                        </ListItemIcon>

                        <ListItemText primary={component.name} />

                        {isExpanded ? (
                            <ExpandLess fontSize="small" />
                        ) : (
                            <ExpandMore fontSize="small" />
                        )}
                    </ListItemButton>

                    <Collapse in={isExpanded} timeout="auto" unmountOnExit>
                        <List component="ul" disablePadding>
                            {children?.map((child) => renderComponent(child, true))}
                        </List>
                    </Collapse>
                </Box>
            )
        }

        if (!component.path) return null

        return (
            <Box component="li" key={component.path} sx={{ listStyle: "none" }}>
                <ListItemButton
                    component={Link}
                    to={component.path}
                    selected={selected}
                    // The highlight is decoration; this is what tells a screen reader which
                    // entry is the current page.
                    aria-current={selected ? "page" : undefined}
                    onClick={() => setMobileOpen(false)}
                    sx={{ mb: 0.25, pl: nested ? 4 : 1.5 }}
                >
                    <ListItemIcon>
                        <Icon fontSize="small" />
                    </ListItemIcon>

                    <ListItemText primary={component.name} />
                </ListItemButton>
            </Box>
        )
    }

    const drawer = (
        <Box sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
            <Box
                sx={{
                    px: 2.5,
                    height: 64,
                    display: "flex",
                    alignItems: "center",
                    flexShrink: 0,
                }}
            >
                <Brand to="/" />
            </Box>

            <Divider />

            <Box
                component="nav"
                aria-label="Sections"
                sx={{ flex: 1, overflowY: "auto", px: 1.5, py: 2 }}
            >
                <List component="ul" disablePadding>
                    {DashboardComponents.map((component) => renderComponent(component))}
                </List>
            </Box>

            <Divider />

            <Box sx={{ p: 1.5 }}>
                <Stack direction="row" sx={{ alignItems: "center", gap: 0.5 }}>
                    <ButtonBase
                        onClick={(event) => setUserMenu(event.currentTarget)}
                        aria-haspopup="menu"
                        aria-expanded={userMenu !== null}
                        aria-label={`Account menu for ${displayName}`}
                        sx={{
                            flex: 1,
                            minWidth: 0,
                            gap: 1.25,
                            px: 1,
                            py: 1,
                            borderRadius: 2,
                            justifyContent: "flex-start",
                            textAlign: "left",
                            "&:hover": { backgroundColor: "action.hover" },
                        }}
                    >
                        <Avatar
                            sx={{
                                bgcolor: "primary.main",
                                color: "primary.contrastText",
                                width: 34,
                                height: 34,
                                fontSize: "0.8125rem",
                            }}
                        >
                            {initials}
                        </Avatar>

                        <Box sx={{ minWidth: 0 }}>
                            <Typography variant="body2" noWrap sx={{ fontWeight: 600 }}>
                                {displayName}
                            </Typography>

                            <Typography variant="caption" noWrap sx={{ color: "text.secondary", display: "block" }}>
                                {user.email}
                            </Typography>
                        </Box>
                    </ButtonBase>

                    <ThemeToggle size="small" />
                </Stack>
            </Box>
        </Box>
    )

    return (
        <Box sx={{ display: "flex", minHeight: "100vh", width: "100%" }}>
            <MuiLink
                href={`#${MAIN_CONTENT_ID}`}
                className="skip-link"
                sx={{
                    position: "fixed",
                    top: 8,
                    left: 8,
                    zIndex: (muiTheme) => muiTheme.zIndex.tooltip + 2,
                    px: 2,
                    py: 1,
                    borderRadius: 1,
                    backgroundColor: "background.paper",
                    border: "1px solid",
                    borderColor: "divider",
                }}
            >
                Skip to main content
            </MuiLink>

            <AppBar
                position="fixed"
                sx={{ display: { xs: "flex", md: "none" } }}
            >
                <Toolbar sx={{ gap: 1 }}>
                    <Tooltip title="Open navigation">
                        <IconButton
                            color="inherit"
                            edge="start"
                            aria-label="Open navigation"
                            aria-expanded={mobileOpen}
                            onClick={() => setMobileOpen(true)}
                        >
                            <MenuIcon />
                        </IconButton>
                    </Tooltip>

                    <Brand to="/" size="small" />

                    <Box sx={{ flex: 1 }} />

                    <ThemeToggle size="small" />
                </Toolbar>
            </AppBar>

            <Box
                component="div"
                sx={{ width: { md: NAV_WIDTH }, flexShrink: { md: 0 } }}
            >
                <Drawer
                    variant={isMobile ? "temporary" : "permanent"}
                    open={isMobile ? mobileOpen : true}
                    onClose={() => setMobileOpen(false)}
                    ModalProps={{ keepMounted: true }}
                    sx={{
                        "& .MuiDrawer-paper": {
                            boxSizing: "border-box",
                            width: NAV_WIDTH,
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
                id={MAIN_CONTENT_ID}
                tabIndex={-1}
                sx={{
                    flexGrow: 1,
                    minWidth: 0,
                    width: "100%",
                    pt: { xs: 11, md: 5 },
                    px: { xs: 2, sm: 3, md: 5 },
                    pb: { xs: 6, md: 8 },
                    outline: "none",
                }}
            >
                {/* One measure for every route, so page titles and table edges line up as the
                    user moves between sections. */}
                <Box sx={{ maxWidth: 1180, mx: "auto", width: "100%" }}>
                    <Outlet />
                </Box>
            </Box>

            <Menu
                anchorEl={userMenu}
                open={userMenu !== null}
                onClose={() => setUserMenu(null)}
                anchorOrigin={{ vertical: "top", horizontal: "left" }}
                transformOrigin={{ vertical: "bottom", horizontal: "left" }}
                slotProps={{ paper: { sx: { minWidth: 220 } } }}
            >
                <Box sx={{ px: 1.5, py: 1 }}>
                    <Typography variant="body2" sx={{ fontWeight: 600 }} noWrap>
                        {displayName}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary" }} noWrap>
                        {user.email}
                    </Typography>
                </Box>

                <Divider sx={{ my: 0.5 }} />

                <MenuItem
                    component={Link}
                    to="/account"
                    onClick={() => {
                        setUserMenu(null)
                        setMobileOpen(false)
                    }}
                >
                    <ListItemIcon>
                        <ManageAccounts fontSize="small" />
                    </ListItemIcon>
                    Account settings
                </MenuItem>

                <MenuItem onClick={() => void handleLogout()} sx={{ color: "error.main" }}>
                    <ListItemIcon>
                        <Logout fontSize="small" sx={{ color: "error.main" }} />
                    </ListItemIcon>
                    Sign out
                </MenuItem>
            </Menu>
        </Box>
    )
}
