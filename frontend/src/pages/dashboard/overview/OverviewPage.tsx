import {
    AdminPanelSettings,
    ChevronRight,
    Devices,
    ManageAccounts,
    MarkEmailReadOutlined,
    ShieldOutlined,
} from "@mui/icons-material"
import {
    Box,
    Button,
    Chip,
    Paper,
    Skeleton,
    Stack,
    Typography,
} from "@mui/material"
import { alpha } from "@mui/material/styles"
import type { ElementType, ReactNode } from "react"
import { useCallback, useEffect, useState } from "react"
import { Link } from "react-router"
import PageHeader from "../../../components/dashboard/PageHeader.tsx"
import Section from "../../../components/ui/Section.tsx"
import { RetryButton } from "../../../components/ui/StateView.tsx"
import { useUser } from "../../../hooks/useUser.ts"
import { Permissions, usePermissions } from "../../../hooks/usePermissions.ts"
import { accountApi } from "../../../api/account.ts"

/** `null` while the count is unknown — the row renders a placeholder rather than a zero. */
type SessionsState = "loading" | "loaded" | "failed"

type StatusTone = "good" | "attention" | "neutral"

type StatusRowProps = {
    icon: ElementType
    label: string
    /** The state itself, in three words or fewer — this is the scannable part. */
    state: ReactNode
    /** Why it matters and what happens next. */
    detail: ReactNode
    tone: StatusTone
    action?: ReactNode
}

/**
 * One line of the security summary.
 *
 * Colour is never the only signal: the chip carries the state as text, and the icon shape
 * differs per row, so the summary still reads on a greyscale or high-contrast display.
 */
function StatusRow({ icon: Icon, label, state, detail, tone, action }: StatusRowProps) {
    const color = tone === "good" ? "success" : tone === "attention" ? "warning" : "info"

    return (
        <Stack
            direction={{ xs: "column", sm: "row" }}
            sx={{
                gap: { xs: 1.5, sm: 2 },
                alignItems: { sm: "center" },
                justifyContent: "space-between",
            }}
        >
            <Stack direction="row" sx={{ gap: 1.75, alignItems: "flex-start", minWidth: 0 }}>
                <Box
                    aria-hidden
                    sx={{
                        display: "grid",
                        placeItems: "center",
                        flexShrink: 0,
                        width: 38,
                        height: 38,
                        borderRadius: 2,
                        color: `${color}.main`,
                        backgroundColor: (theme) =>
                            alpha(theme.palette[color].main, theme.palette.mode === "dark" ? 0.18 : 0.1),
                    }}
                >
                    <Icon fontSize="small" />
                </Box>

                <Box sx={{ minWidth: 0 }}>
                    <Stack
                        direction="row"
                        sx={{ gap: 1, alignItems: "center", flexWrap: "wrap" }}
                    >
                        <Typography variant="subtitle2">{label}</Typography>

                        <Chip size="small" variant="outlined" color={color} label={state} />
                    </Stack>

                    <Typography variant="body2" sx={{ mt: 0.5, color: "text.secondary" }}>
                        {detail}
                    </Typography>
                </Box>
            </Stack>

            {action && <Box sx={{ flexShrink: 0, pl: { xs: 7, sm: 0 } }}>{action}</Box>}
        </Stack>
    )
}

type DestinationProps = {
    icon: ElementType
    title: string
    description: string
    to: string
}

/** A whole-tile link, so the destination is one focusable target rather than a card plus button. */
function Destination({ icon: Icon, title, description, to }: DestinationProps) {
    return (
        <Paper
            component={Link}
            to={to}
            variant="outlined"
            sx={{
                display: "flex",
                gap: 1.75,
                alignItems: "center",
                p: 2,
                borderRadius: 3,
                textDecoration: "none",
                color: "text.primary",
                transition: "background-color 120ms ease, border-color 120ms ease",
                "&:hover": { backgroundColor: "action.hover", borderColor: "primary.main" },
            }}
        >
            <Box aria-hidden sx={{ display: "flex", color: "text.secondary" }}>
                <Icon />
            </Box>

            <Box sx={{ minWidth: 0, flex: 1 }}>
                <Typography variant="subtitle2">{title}</Typography>
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    {description}
                </Typography>
            </Box>

            <ChevronRight aria-hidden sx={{ color: "text.disabled" }} />
        </Paper>
    )
}

export default function OverviewPage() {
    const user = useUser()
    const permissions = usePermissions()
    const [sessionCount, setSessionCount] = useState<number | null>(null)
    const [sessionsState, setSessionsState] = useState<SessionsState>("loading")

    const isAdmin = permissions.hasAny([
        Permissions.ADMIN_USER_READ,
        Permissions.ADMIN_CLIENT_READ,
        Permissions.ADMIN_ROLE_READ,
        Permissions.ADMIN_AUDIT_READ,
    ])

    // The state starts at "loading", so the fetch itself never has to announce that it
    // began — only how it ended. That also keeps this callable straight from an effect.
    const loadSessions = useCallback(() => {
        accountApi
            .sessions()
            .then(({ data }) => {
                setSessionCount(data.length)
                setSessionsState("loaded")
            })
            .catch(() => {
                // A failed count and a count of zero mean very different things to someone
                // checking who is signed in, so they are never collapsed into one state.
                setSessionCount(null)
                setSessionsState("failed")
            })
    }, [])

    useEffect(() => {
        loadSessions()
    }, [loadSessions])

    return (
        <Stack spacing={4} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title={`Welcome back, ${user.firstName || user.username}`}
                description="Your identity across every connected service. Anything that needs your attention is listed below."
            />

            <Section
                title="Security status"
                description="What is currently protecting this account."
            >
                <Stack sx={{ gap: 3 }}>
                    <StatusRow
                        icon={MarkEmailReadOutlined}
                        label="Email address"
                        state={user.email_verified ? "Verified" : "Not verified"}
                        tone={user.email_verified ? "good" : "attention"}
                        detail={
                            user.email_verified
                                ? `${user.email} is confirmed and can be used to recover this account.`
                                : `${user.email} is unconfirmed, so password recovery and some sign-ins will be refused.`
                        }
                        action={
                            !user.email_verified && (
                                <Button component={Link} to="/account" size="small" variant="contained">
                                    Verify email
                                </Button>
                            )
                        }
                    />

                    <StatusRow
                        icon={ShieldOutlined}
                        label="Two-factor authentication"
                        state={user.mfa_enabled ? "On" : "Off"}
                        tone={user.mfa_enabled ? "good" : "attention"}
                        detail={
                            user.mfa_enabled
                                ? "A second factor is required when signing in from a new device."
                                : "A stolen password is enough to sign in as you. Add an authenticator app to stop that."
                        }
                        action={
                            <Button
                                component={Link}
                                to="/account"
                                size="small"
                                variant={user.mfa_enabled ? "outlined" : "contained"}
                            >
                                {user.mfa_enabled ? "Manage" : "Turn on"}
                            </Button>
                        }
                    />

                    <StatusRow
                        icon={Devices}
                        label="Active sessions"
                        tone={sessionsState === "failed" ? "neutral" : "good"}
                        state={
                            sessionsState === "loading" ? (
                                <Skeleton variant="text" width={48} />
                            ) : sessionsState === "failed" ? (
                                "Unknown"
                            ) : (
                                `${sessionCount} signed in`
                            )
                        }
                        detail={
                            sessionsState === "loading"
                                ? "Counting the devices signed in to your account…"
                                : sessionsState === "failed"
                                  ? "We could not reach the session list just now."
                                  : sessionCount === 1
                                    ? "Only this device is signed in. Sign out anything you do not recognise."
                                    : `${sessionCount} devices are signed in. Sign out anything you do not recognise.`
                        }
                        action={
                            sessionsState === "failed" ? (
                                <RetryButton
                                    onRetry={() => {
                                        setSessionsState("loading")
                                        loadSessions()
                                    }}
                                    label="Retry"
                                />
                            ) : (
                                <Button component={Link} to="/account" size="small" variant="outlined">
                                    Review devices
                                </Button>
                            )
                        }
                    />
                </Stack>
            </Section>

            <Section title="Go to" description="The rest of your account, and the tools you can reach.">
                <Box
                    sx={{
                        display: "grid",
                        gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" },
                        gap: 2,
                    }}
                >
                    <Destination
                        icon={ManageAccounts}
                        title="Account settings"
                        description="Profile, password, email, two-factor and linked providers."
                        to="/account"
                    />

                    <Destination
                        icon={Devices}
                        title="Devices & sessions"
                        description="See where you are signed in and revoke anything unfamiliar."
                        to="/account"
                    />

                    {isAdmin && (
                        <Destination
                            icon={AdminPanelSettings}
                            title="Administration"
                            description="Users, OAuth applications, roles and the audit trail."
                            to="/admin"
                        />
                    )}
                </Box>
            </Section>
        </Stack>
    )
}
