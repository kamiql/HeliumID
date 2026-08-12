import { Avatar, Box, Button, Card, CardContent, Stack, Typography } from "@mui/material"
import { Apps, History, People, Security } from "@mui/icons-material"
import { Link } from "react-router"
import PageHeader from "../../../components/dashboard/PageHeader.tsx"
import { Permissions, usePermissions } from "../../../hooks/usePermissions.ts"

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

    const visible = SECTIONS.filter((section) => permissions.has(section.require))

    return (
        <Stack spacing={4} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title="Admin"
                description="Administer users, applications, roles and the audit trail."
            />

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: {
                        xs: "1fr",
                        md: "repeat(2, 1fr)",
                    },
                    gap: 2,
                }}
            >
                {visible.map((section) => {
                    const Icon = section.icon

                    return (
                        <Card key={section.to}>
                            <CardContent>
                                <Stack spacing={2}>
                                    <Avatar sx={{ bgcolor: section.color }}>
                                        <Icon />
                                    </Avatar>

                                    <Box>
                                        <Typography variant="h6" sx={{ fontWeight: 600 }}>
                                            {section.title}
                                        </Typography>

                                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                            {section.description}
                                        </Typography>
                                    </Box>

                                    <Button component={Link} to={section.to} variant="outlined">
                                        Open
                                    </Button>
                                </Stack>
                            </CardContent>
                        </Card>
                    )
                })}
            </Box>
        </Stack>
    )
}
