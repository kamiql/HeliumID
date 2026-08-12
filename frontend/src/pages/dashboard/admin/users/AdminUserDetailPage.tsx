import {
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    Divider,
    MenuItem,
    OutlinedInput,
    Select,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableRow,
    TextField,
    Typography,
} from "@mui/material"
import { ArrowBack } from "@mui/icons-material"
import { useCallback, useEffect, useState } from "react"
import { Link, useParams } from "react-router"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import UserStatusChip from "./UserStatusChip.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { Permissions, usePermissions } from "../../../../hooks/usePermissions.ts"
import { formatDateTime, formatRelative, humanize } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { AdminUser, AuditRecord, Role, SessionInfo } from "../../../../api/types.ts"

const STATUS_OPTIONS = ["ACTIVE", "SUSPENDED", "LOCKED", "PENDING_EMAIL_VERIFICATION"] as const

export default function AdminUserDetailPage() {
    const { userId = "" } = useParams()
    const { confirm } = useConfirm()
    const permissions = usePermissions()

    const canWrite = permissions.has(Permissions.ADMIN_USER_WRITE)
    const canReadAudit = permissions.has(Permissions.ADMIN_AUDIT_READ)

    const [user, setUser] = useState<AdminUser | null>(null)
    const [roles, setRoles] = useState<Role[]>([])
    const [sessions, setSessions] = useState<SessionInfo[]>([])
    const [audit, setAudit] = useState<AuditRecord[]>([])

    const [status, setStatus] = useState("")
    const [assigned, setAssigned] = useState<string[]>([])
    const [error, setError] = useState<unknown>(null)
    const [busy, setBusy] = useState(false)

    const loadUser = useCallback(() => {
        adminApi
            .user(userId)
            .then(({ data }) => {
                setUser(data)
                setStatus(data.status)
                setAssigned(data.roles)
            })
            .catch((caught: unknown) => setError(caught))
    }, [userId])

    const loadSessions = useCallback(() => {
        adminApi
            .userSessions(userId)
            .then(({ data }) => setSessions(data))
            .catch(() => setSessions([]))
    }, [userId])

    useEffect(() => {
        loadUser()
        loadSessions()
        adminApi
            .roles()
            .then(({ data }) => setRoles(data))
            .catch(() => setRoles([]))
    }, [loadUser, loadSessions])

    useEffect(() => {
        if (!canReadAudit) return
        adminApi
            .audit({ user_id: userId, limit: 50 })
            .then(({ data }) => setAudit(data.items))
            .catch(() => setAudit([]))
    }, [userId, canReadAudit])

    const handleStatus = async () => {
        if (!user || status === user.status) return

        const confirmed = await confirm({
            title: "Change account status?",
            message: `This account will be set to ${status.replace(/_/g, " ").toLowerCase()}.`,
            confirmText: "Change status",
        })
        if (!confirmed) return

        try {
            setBusy(true)
            setError(null)
            await adminApi.updateUserStatus(userId, { status })
            loadUser()
            notify("Account status updated.", "success")
        } catch (caught) {
            setError(caught)
        } finally {
            setBusy(false)
        }
    }

    const handleRoles = async () => {
        try {
            setBusy(true)
            setError(null)
            await adminApi.assignRoles(userId, { roles: assigned })
            loadUser()
            notify("Roles updated.", "success")
        } catch (caught) {
            setError(caught)
        } finally {
            setBusy(false)
        }
    }

    const handleRevokeAll = async () => {
        const confirmed = await confirm({
            title: "Revoke all sessions?",
            message: "Every device signed in as this user will be signed out immediately.",
            confirmText: "Revoke all",
        })
        if (!confirmed) return

        try {
            setBusy(true)
            setError(null)
            const { data } = await adminApi.revokeUserSessions(userId)
            loadSessions()
            notify(`Revoked ${data.revoked} session(s).`, "success")
        } catch (caught) {
            setError(caught)
        } finally {
            setBusy(false)
        }
    }

    if (!user) {
        return (
            <Stack spacing={3} sx={{ maxWidth: 1000, mx: "auto" }}>
                <PageHeader title="User" />
                {error !== null && <ErrorAlert error={error} />}
            </Stack>
        )
    }

    const details: [string, string][] = [
        ["User ID", user.id],
        ["Username", user.username],
        ["Email", `${user.email}${user.email_verified ? "" : " (unverified)"}`],
        ["Name", [user.firstName, user.lastName].filter(Boolean).join(" ") || "—"],
        ["Created", formatDateTime(user.created_at)],
        ["Updated", formatDateTime(user.updated_at)],
    ]

    return (
        <Stack spacing={3} sx={{ maxWidth: 1000, mx: "auto" }}>
            <PageHeader
                title={user.username}
                description={user.email}
                actions={
                    <Button component={Link} to="/admin/users" startIcon={<ArrowBack />} variant="text">
                        All users
                    </Button>
                }
            />

            {error !== null && <ErrorAlert error={error} />}

            <Card>
                <CardContent>
                    <Stack spacing={3}>
                        <Box>
                            <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1 }}>
                                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                                    Account
                                </Typography>
                                <UserStatusChip status={user.status} />
                            </Stack>

                            <Box
                                sx={{
                                    display: "grid",
                                    gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" },
                                    gap: 2,
                                    mt: 2,
                                }}
                            >
                                {details.map(([label, value]) => (
                                    <Box key={label}>
                                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                            {label}
                                        </Typography>
                                        <Typography sx={{ mt: 0.25, wordBreak: "break-all" }}>
                                            {value}
                                        </Typography>
                                    </Box>
                                ))}
                            </Box>
                        </Box>

                        <Divider />

                        <Stack
                            direction={{ xs: "column", sm: "row" }}
                            spacing={2}
                            sx={{ alignItems: { sm: "center" } }}
                        >
                            <TextField
                                select
                                size="small"
                                label="Status"
                                value={status}
                                disabled={!canWrite}
                                onChange={(event) => setStatus(event.target.value)}
                                sx={{ minWidth: 260 }}
                            >
                                {STATUS_OPTIONS.map((option) => (
                                    <MenuItem key={option} value={option}>
                                        {option.replace(/_/g, " ")}
                                    </MenuItem>
                                ))}
                            </TextField>

                            <Button
                                variant="contained"
                                disabled={!canWrite || busy || status === user.status}
                                onClick={() => void handleStatus()}
                            >
                                Apply status
                            </Button>
                        </Stack>
                    </Stack>
                </CardContent>
            </Card>

            <Card>
                <CardContent>
                    <Stack spacing={2}>
                        <Typography variant="h6" sx={{ fontWeight: 600 }}>
                            Roles
                        </Typography>

                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Roles are flattened into a permission set; they do not inherit from
                            each other.
                        </Typography>

                        <Select
                            multiple
                            size="small"
                            value={assigned}
                            disabled={!canWrite}
                            onChange={(event) =>
                                setAssigned(
                                    typeof event.target.value === "string"
                                        ? event.target.value.split(",")
                                        : event.target.value,
                                )
                            }
                            input={<OutlinedInput />}
                            renderValue={(selected) => (
                                <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                                    {selected.map((name) => (
                                        <Chip key={name} label={name} size="small" />
                                    ))}
                                </Stack>
                            )}
                        >
                            {roles.map((entry) => (
                                <MenuItem key={entry.name} value={entry.name}>
                                    {entry.name}
                                </MenuItem>
                            ))}
                        </Select>

                        <Box>
                            <Button
                                variant="contained"
                                disabled={!canWrite || busy}
                                onClick={() => void handleRoles()}
                            >
                                Save roles
                            </Button>
                        </Box>
                    </Stack>
                </CardContent>
            </Card>

            <Card>
                <CardContent>
                    <Stack spacing={2}>
                        <Stack
                            direction="row"
                            sx={{ alignItems: "center", justifyContent: "space-between", gap: 2 }}
                        >
                            <Typography variant="h6" sx={{ fontWeight: 600 }}>
                                Sessions ({sessions.length})
                            </Typography>

                            <Button
                                variant="outlined"
                                color="error"
                                size="small"
                                disabled={!canWrite || busy || sessions.length === 0}
                                onClick={() => void handleRevokeAll()}
                            >
                                Revoke all
                            </Button>
                        </Stack>

                        {sessions.length === 0 ? (
                            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                No active sessions.
                            </Typography>
                        ) : (
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell>Device</TableCell>
                                        <TableCell>Last seen</TableCell>
                                        <TableCell>Expires</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {sessions.map((session) => (
                                        <TableRow key={session.id}>
                                            <TableCell>{session.device ?? "Unknown device"}</TableCell>
                                            <TableCell>{formatRelative(session.last_seen_at)}</TableCell>
                                            <TableCell>{formatRelative(session.expires_at)}</TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        )}
                    </Stack>
                </CardContent>
            </Card>

            {canReadAudit && (
                <Card>
                    <CardContent>
                        <Stack spacing={2}>
                            <Typography variant="h6" sx={{ fontWeight: 600 }}>
                                Audit trail
                            </Typography>

                            {audit.length === 0 ? (
                                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                    No audit records for this account.
                                </Typography>
                            ) : (
                                <Table size="small">
                                    <TableHead>
                                        <TableRow>
                                            <TableCell>When</TableCell>
                                            <TableCell>Event</TableCell>
                                            <TableCell>Outcome</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {audit.map((record) => (
                                            <TableRow key={record.id}>
                                                <TableCell>{formatDateTime(record.created_at)}</TableCell>
                                                <TableCell>{humanize(record.event_type)}</TableCell>
                                                <TableCell>
                                                    <Chip
                                                        size="small"
                                                        label={record.outcome.toLowerCase()}
                                                        color={
                                                            record.outcome.toUpperCase() === "SUCCESS"
                                                                ? "success"
                                                                : "error"
                                                        }
                                                        variant="outlined"
                                                    />
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            )}
                        </Stack>
                    </CardContent>
                </Card>
            )}
        </Stack>
    )
}
