import {
    Box,
    Button,
    Chip,
    MenuItem,
    OutlinedInput,
    Select,
    Stack,
    Tab,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Tabs,
    TextField,
    Typography,
} from "@mui/material"
import { ArrowBack, DevicesOther, FactCheck, PendingActions } from "@mui/icons-material"
import { useCallback, useEffect, useState } from "react"
import { Link, useParams } from "react-router"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import DefinitionList, {
    type DefinitionItem,
} from "../../../../components/ui/DefinitionList.tsx"
import Section from "../../../../components/ui/Section.tsx"
import {
    EmptyState,
    ListSkeleton,
    LoadingState,
    TableSkeleton,
    TableStateRow,
} from "../../../../components/ui/StateView.tsx"
import UserStatusChip from "./UserStatusChip.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { ErrorCode, toHeliumError } from "../../../../api/problem.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { Permissions, usePermissions } from "../../../../hooks/usePermissions.ts"
import { formatDateTime, formatRelative, humanize } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { AdminUser, AuditRecord, Role, SessionInfo } from "../../../../api/types.ts"

const STATUS_OPTIONS = ["ACTIVE", "SUSPENDED", "LOCKED", "PENDING_EMAIL_VERIFICATION"] as const

type TabKey = "overview" | "roles" | "sessions" | "audit"

/** Order-insensitive: assigning the same roles in a different order is not a change. */
function sameRoles(left: string[], right: string[]): boolean {
    if (left.length !== right.length) return false
    const sorted = [...right].sort()
    return [...left].sort().every((name, index) => name === sorted[index])
}

/** Wires a tab to its panel, so a screen reader announces which section it landed in. */
function tabProps(key: TabKey) {
    return { value: key, id: `user-tab-${key}`, "aria-controls": `user-panel-${key}` }
}

function panelProps(key: TabKey) {
    return { role: "tabpanel", id: `user-panel-${key}`, "aria-labelledby": `user-tab-${key}` }
}

/** Sits beside a save button so the user can see that state is waiting to be written. */
function UnsavedHint() {
    return (
        <Chip
            size="small"
            color="warning"
            variant="outlined"
            icon={<PendingActions fontSize="small" />}
            label="Unsaved change"
        />
    )
}

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

    const [loading, setLoading] = useState(true)
    const [sessionsLoading, setSessionsLoading] = useState(true)
    const [auditLoading, setAuditLoading] = useState(canReadAudit)
    const [tab, setTab] = useState<TabKey>("overview")

    // These flags start true and are raised again only from explicit retry handlers; a
    // refresh after a status or role change updates the panel in place.
    const loadUser = useCallback(() => {
        adminApi
            .user(userId)
            .then(({ data }) => {
                setUser(data)
                setStatus(data.status)
                setAssigned(data.roles)
                setLoading(false)
            })
            .catch((caught: unknown) => {
                setError(caught)
                setLoading(false)
            })
    }, [userId])

    const loadSessions = useCallback(() => {
        adminApi
            .userSessions(userId)
            .then(({ data }) => {
                setSessions(data)
                setSessionsLoading(false)
            })
            .catch(() => {
                setSessions([])
                setSessionsLoading(false)
            })
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
        // `auditLoading` is initialised from `canReadAudit`, so the fetch only reports how it
        // ended.
        adminApi
            .audit({ user_id: userId, limit: 50 })
            .then(({ data }) => {
                setAudit(data.items)
                setAuditLoading(false)
            })
            .catch(() => {
                setAudit([])
                setAuditLoading(false)
            })
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

    const breadcrumbs = [
        { label: "Admin", to: "/admin" },
        { label: "Users", to: "/admin/users" },
    ]

    const backAction = (
        <Button component={Link} to="/admin/users" startIcon={<ArrowBack />} variant="text">
            All users
        </Button>
    )

    if (!user) {
        // Three different situations used to render the same bare header: still loading, the
        // account does not exist, and the request failed. They are told apart here.
        const notFound = error !== null && toHeliumError(error).is(ErrorCode.NOT_FOUND)

        return (
            <Stack spacing={3} sx={{ maxWidth: 1100, mx: "auto" }}>
                <PageHeader
                    title={loading ? "Loading account…" : notFound ? "Account not found" : "Account"}
                    breadcrumbs={breadcrumbs}
                    actions={backAction}
                />

                {loading ? (
                    <Section title="Account" description="Fetching this account from the directory.">
                        <LoadingState label="Loading account…" />
                    </Section>
                ) : notFound ? (
                    <Section title="Account" disableBodyPadding>
                        <EmptyState
                            icon={FactCheck}
                            title="No account with that identifier"
                            description="It may have been deleted, or the link you followed may contain an old user ID."
                            action={
                                <Button component={Link} to="/admin/users" variant="outlined">
                                    Back to users
                                </Button>
                            }
                        />
                    </Section>
                ) : (
                    <ErrorAlert
                        error={error}
                        title="This account could not be loaded"
                        onRetry={() => {
                            setLoading(true)
                            setError(null)
                            loadUser()
                        }}
                    />
                )}
            </Stack>
        )
    }

    const statusDirty = status !== user.status
    const rolesDirty = !sameRoles(assigned, user.roles)

    const details: DefinitionItem[] = [
        { label: "User ID", value: user.id, mono: true, wide: true },
        { label: "Username", value: user.username },
        {
            label: "Email",
            value: `${user.email}${user.email_verified ? "" : " (unverified)"}`,
        },
        {
            label: "Name",
            value: [user.firstName, user.lastName].filter(Boolean).join(" ") || "—",
        },
        { label: "Roles", value: user.roles.join(", ") || "None" },
        { label: "Created", value: formatDateTime(user.created_at) },
        { label: "Updated", value: formatDateTime(user.updated_at) },
    ]

    return (
        <Stack spacing={3} sx={{ maxWidth: 1100, mx: "auto" }}>
            <PageHeader
                title={user.username}
                description={user.email}
                breadcrumbs={breadcrumbs}
                meta={<UserStatusChip status={user.status} />}
                actions={backAction}
            />

            {error !== null && <ErrorAlert error={error} />}

            <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
                <Tabs
                    value={tab}
                    onChange={(_event, next: TabKey) => setTab(next)}
                    variant="scrollable"
                    scrollButtons="auto"
                    allowScrollButtonsMobile
                    aria-label="Account sections"
                >
                    <Tab {...tabProps("overview")} label="Overview" />
                    <Tab {...tabProps("roles")} label="Roles" />
                    <Tab
                        {...tabProps("sessions")}
                        label={sessionsLoading ? "Sessions" : `Sessions (${sessions.length})`}
                    />
                    {canReadAudit && <Tab {...tabProps("audit")} label="Audit" />}
                </Tabs>
            </Box>

            {tab === "overview" && (
                <Stack spacing={3} {...panelProps("overview")}>
                    <Section title="Details" description="What the directory holds for this account.">
                        <DefinitionList items={details} columns={2} />
                    </Section>

                    <Section
                        title="Account status"
                        description="Suspending or locking an account stops every new sign-in at once. Existing sessions are not revoked by this control."
                        banner={statusDirty && <UnsavedHint />}
                    >
                        <Stack
                            direction={{ xs: "column", sm: "row" }}
                            sx={{ gap: 2, alignItems: { sm: "flex-start" } }}
                        >
                            <TextField
                                select
                                size="small"
                                label="Status"
                                value={status}
                                disabled={!canWrite}
                                onChange={(event) => setStatus(event.target.value)}
                                helperText={
                                    statusDirty
                                        ? `Not applied yet — currently ${user.status
                                              .replace(/_/g, " ")
                                              .toLowerCase()}.`
                                        : "Matches the stored status."
                                }
                                sx={{ minWidth: { sm: 260 } }}
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
                    </Section>
                </Stack>
            )}

            {tab === "roles" && (
                <Box {...panelProps("roles")}>
                    <Section
                        title="Assigned roles"
                        description="Roles are flattened into a permission set; they do not inherit from each other."
                        banner={rolesDirty && <UnsavedHint />}
                    >
                        <Stack spacing={2}>
                            <Select
                                multiple
                                size="small"
                                value={assigned}
                                disabled={!canWrite}
                                aria-label="Assigned roles"
                                onChange={(event) =>
                                    setAssigned(
                                        typeof event.target.value === "string"
                                            ? event.target.value.split(",")
                                            : event.target.value,
                                    )
                                }
                                input={<OutlinedInput />}
                                renderValue={(selected) =>
                                    selected.length === 0 ? (
                                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                            No roles assigned
                                        </Typography>
                                    ) : (
                                        <Stack direction="row" sx={{ gap: 0.5, flexWrap: "wrap" }}>
                                            {selected.map((name) => (
                                                <Chip key={name} label={name} size="small" />
                                            ))}
                                        </Stack>
                                    )
                                }
                            >
                                {roles.map((entry) => (
                                    <MenuItem key={entry.name} value={entry.name}>
                                        {entry.name}
                                    </MenuItem>
                                ))}
                            </Select>

                            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                {rolesDirty
                                    ? `Saved value: ${user.roles.join(", ") || "no roles"}.`
                                    : "These are the roles currently stored for the account."}
                            </Typography>

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
                    </Section>
                </Box>
            )}

            {tab === "sessions" && (
                <Box {...panelProps("sessions")}>
                    <Section
                        title="Sessions"
                        description="Every browser or device holding a live session for this account."
                        disableBodyPadding
                        actions={
                            <Button
                                variant="outlined"
                                color="error"
                                size="small"
                                disabled={!canWrite || busy || sessions.length === 0}
                                onClick={() => void handleRevokeAll()}
                            >
                                Revoke all
                            </Button>
                        }
                    >
                        <TableContainer sx={{ overflowX: "auto" }}>
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell>Device</TableCell>
                                        <TableCell>Last seen</TableCell>
                                        <TableCell
                                            sx={{ display: { xs: "none", sm: "table-cell" } }}
                                        >
                                            Expires
                                        </TableCell>
                                    </TableRow>
                                </TableHead>

                                <TableBody>
                                    {sessionsLoading && <TableSkeleton rows={3} columns={3} />}

                                    {!sessionsLoading &&
                                        sessions.map((session) => (
                                            <TableRow key={session.id}>
                                                <TableCell>
                                                    {session.device ?? "Unknown device"}
                                                </TableCell>
                                                <TableCell>
                                                    {formatRelative(session.last_seen_at)}
                                                </TableCell>
                                                <TableCell
                                                    sx={{
                                                        display: { xs: "none", sm: "table-cell" },
                                                    }}
                                                >
                                                    {formatRelative(session.expires_at)}
                                                </TableCell>
                                            </TableRow>
                                        ))}

                                    {!sessionsLoading && sessions.length === 0 && (
                                        <TableStateRow columns={3}>
                                            <EmptyState
                                                dense
                                                icon={DevicesOther}
                                                title="No active sessions"
                                                description="Nobody is signed in as this account right now."
                                            />
                                        </TableStateRow>
                                    )}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </Section>
                </Box>
            )}

            {tab === "audit" && canReadAudit && (
                <Box {...panelProps("audit")}>
                    <Section
                        title="Audit trail"
                        description="The 50 most recent security events recorded for this account."
                        disableBodyPadding
                    >
                        {auditLoading ? (
                            <Box sx={{ p: 2.5 }}>
                                <ListSkeleton rows={4} lines={1} />
                            </Box>
                        ) : audit.length === 0 ? (
                            <EmptyState
                                icon={FactCheck}
                                title="No audit records"
                                description="Nothing has been recorded against this account yet, or the events have aged out of retention."
                            />
                        ) : (
                            <TableContainer sx={{ overflowX: "auto" }}>
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
                                                <TableCell sx={{ whiteSpace: "nowrap" }}>
                                                    {formatDateTime(record.created_at)}
                                                </TableCell>
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
                            </TableContainer>
                        )}
                    </Section>
                </Box>
            )}
        </Stack>
    )
}
