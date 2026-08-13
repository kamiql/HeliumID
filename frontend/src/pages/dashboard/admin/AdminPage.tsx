import { Box, Paper, Stack, Typography } from "@mui/material"
import { Apps, ChevronRight, History, People, Security } from "@mui/icons-material"
import { Link } from "react-router"
import PageHeader from "../../../components/dashboard/PageHeader.tsx"
import Section from "../../../components/ui/Section.tsx"
import { EmptyState } from "../../../components/ui/StateView.tsx"
import { Permissions, usePermissions } from "../../../hooks/usePermissions.ts"

/**
 * The admin destinations, in the order they are worked through.
 *
 * `color` is kept on each entry but deliberately not rendered: a different hue per section
 * carried no meaning, and colour in this app is reserved for state (enabled, suspended,
 * destructive). The icon and the one-line description do the distinguishing instead.
 */
const SECTIONS = [
    {
        title: "Users",
        description: "Search accounts, change status, assign roles and revoke sessions.",
        to: "/admin/users",
        icon: People,
        color: "primary.main",
        require: Permissions.ADMIN_USER_READ,
    },
    {
        title: "OAuth applications",
        description: "Register relying parties, manage redirect URIs, scopes and secrets.",
        to: "/admin/clients",
        icon: Apps,
        color: "secondary.main",
        require: Permissions.ADMIN_CLIENT_READ,
    },
    {
        title: "Roles & permissions",
        description: "Define custom roles. Built-in roles are read-only.",
        to: "/admin/roles",
        icon: Security,
        color: "success.main",
        require: Permissions.ADMIN_ROLE_READ,
    },
    {
        title: "Audit log",
        description: "Security events, filterable by subject and event type.",
        to: "/admin/audit",
        icon: History,
        color: "warning.main",
        require: Permissions.ADMIN_AUDIT_READ,
    },
] as const

export default function AdminPage() {
    const permissions = usePermissions()

    // Presentation only: every endpoint behind these routes re-checks the same permission
    // server-side, so hiding an entry is a courtesy and not an authorization control.
    const visible = SECTIONS.filter((section) => permissions.has(section.require))

    return (
        <Stack spacing={4} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title="Admin"
                description="Administer users, applications, roles and the audit trail."
                breadcrumbs={[{ label: "Overview", to: "/" }]}
            />

            <Section
                title="Sections"
                description="Only the areas your permissions allow are listed."
                disableBodyPadding={visible.length === 0}
            >
                {visible.length === 0 ? (
                    <EmptyState
                        icon={Security}
                        title="Nothing to administer"
                        description="Your account has no admin read permissions, so there is nothing here yet. Ask an administrator to grant the access you need."
                    />
                ) : (
                    <Box
                        sx={{
                            display: "grid",
                            gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" },
                            gap: 2,
                        }}
                    >
                        {visible.map((section) => {
                            const Icon = section.icon

                            return (
                                <Paper
                                    key={section.to}
                                    component={Link}
                                    to={section.to}
                                    variant="outlined"
                                    sx={{
                                        display: "flex",
                                        gap: 1.75,
                                        alignItems: "flex-start",
                                        p: 2,
                                        borderRadius: 3,
                                        textDecoration: "none",
                                        color: "text.primary",
                                        transition:
                                            "background-color 120ms ease, border-color 120ms ease",
                                        "&:hover": {
                                            backgroundColor: "action.hover",
                                            borderColor: "primary.main",
                                        },
                                    }}
                                >
                                    <Box
                                        aria-hidden
                                        sx={{ display: "flex", mt: 0.25, color: "text.secondary" }}
                                    >
                                        <Icon />
                                    </Box>

                                    <Box sx={{ minWidth: 0, flex: 1 }}>
                                        <Typography variant="subtitle1">{section.title}</Typography>

                                        <Typography
                                            variant="body2"
                                            sx={{ mt: 0.25, color: "text.secondary" }}
                                        >
                                            {section.description}
                                        </Typography>
                                    </Box>

                                    <ChevronRight
                                        aria-hidden
                                        sx={{ mt: 0.25, color: "text.disabled" }}
                                    />
                                </Paper>
                            )
                        })}
                    </Box>
                )}
            </Section>
        </Stack>
    )
}
