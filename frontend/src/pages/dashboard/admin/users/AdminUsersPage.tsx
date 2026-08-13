import {
    Box,
    Button,
    Chip,
    Divider,
    Link as MuiLink,
    MenuItem,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TablePagination,
    TableRow,
    TextField,
    Tooltip,
    Typography,
} from "@mui/material"
import { PersonSearch } from "@mui/icons-material"
import { useEffect, useMemo, useState } from "react"
import { Link, useNavigate } from "react-router"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import Section from "../../../../components/ui/Section.tsx"
import { EmptyState, TableSkeleton, TableStateRow } from "../../../../components/ui/StateView.tsx"
import UserStatusChip from "./UserStatusChip.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { formatDate } from "../../../../lib/format.ts"
import type { AdminUser, Role } from "../../../../api/types.ts"

const STATUSES = [
    "PENDING_EMAIL_VERIFICATION",
    "ACTIVE",
    "SUSPENDED",
    "LOCKED",
    "DELETED",
] as const

/** Columns rendered at every width. The rest are hidden with CSS so `colSpan` stays constant. */
const COLUMN_COUNT = 5

/** How many role chips fit before the rest collapse into a single "+N" affordance. */
const ROLE_CHIP_LIMIT = 2

export default function AdminUsersPage() {
    const navigate = useNavigate()

    const [term, setTerm] = useState("")
    const [debouncedTerm, setDebouncedTerm] = useState("")
    const [status, setStatus] = useState("")
    const [role, setRole] = useState("")
    const [page, setPage] = useState(0)
    const [rowsPerPage, setRowsPerPage] = useState(25)

    const [users, setUsers] = useState<AdminUser[]>([])
    const [total, setTotal] = useState(0)
    const [roles, setRoles] = useState<Role[]>([])
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(true)
    // Bumped by the retry button so the effect below re-runs with the exact same query.
    const [reloadToken, setReloadToken] = useState(0)

    useEffect(() => {
        const handle = window.setTimeout(() => {
            setDebouncedTerm(term.trim())
            setPage(0)
        }, 300)
        return () => window.clearTimeout(handle)
    }, [term])

    useEffect(() => {
        // Best effort: the role filter is a convenience and requires admin:role:read.
        adminApi
            .roles()
            .then(({ data }) => setRoles(data))
            .catch(() => setRoles([]))
    }, [])

    useEffect(() => {
        let active = true

        // `loading` starts true and the retry button raises it again. Not raising it on every
        // filter change is deliberate: the rows stay readable while a new query runs instead
        // of flashing skeletons on each debounced keystroke, and the app shell's progress bar
        // carries the in-flight signal.
        adminApi
            .users({
                q: debouncedTerm || undefined,
                status: status || undefined,
                role: role || undefined,
                limit: rowsPerPage,
                offset: page * rowsPerPage,
            })
            .then(({ data }) => {
                if (!active) return
                setUsers(data.items)
                setTotal(data.total)
                setError(null)
                setLoading(false)
            })
            .catch((caught: unknown) => {
                if (!active) return
                setError(caught)
                setLoading(false)
            })

        return () => {
            active = false
        }
    }, [debouncedTerm, status, role, page, rowsPerPage, reloadToken])

    const roleOptions = useMemo(() => roles.map((entry) => entry.name), [roles])

    // Listed back to the user so "no results" is never confused with "a filter you forgot".
    const activeFilters: { label: string; clear: () => void }[] = []

    if (term) {
        activeFilters.push({ label: `Search: ${term}`, clear: () => setTerm("") })
    }

    if (status) {
        activeFilters.push({
            label: `Status: ${status.replace(/_/g, " ").toLowerCase()}`,
            clear: () => {
                setStatus("")
                setPage(0)
            },
        })
    }

    if (role) {
        activeFilters.push({
            label: `Role: ${role}`,
            clear: () => {
                setRole("")
                setPage(0)
            },
        })
    }

    const clearAll = () => {
        setTerm("")
        setStatus("")
        setRole("")
        setPage(0)
    }

    return (
        <Stack spacing={3} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title="Users"
                description="Search and administer accounts."
                breadcrumbs={[{ label: "Admin", to: "/admin" }]}
                meta={
                    !loading &&
                    error === null && (
                        <Chip
                            size="small"
                            variant="outlined"
                            label={`${total} ${total === 1 ? "account" : "accounts"}`}
                        />
                    )
                }
            />

            <Section
                title="Accounts"
                description="Filters combine; an empty filter matches everything."
                disableBodyPadding
                actions={
                    activeFilters.length > 0 && (
                        <Button size="small" variant="text" onClick={clearAll}>
                            Clear filters
                        </Button>
                    )
                }
            >
                <Box sx={{ p: { xs: 2, sm: 2.5 } }}>
                    <Box
                        sx={{
                            display: "grid",
                            gridTemplateColumns: {
                                xs: "1fr",
                                sm: "minmax(0, 2fr) minmax(0, 1fr) minmax(0, 1fr)",
                            },
                            gap: 2,
                        }}
                    >
                        <TextField
                            size="small"
                            fullWidth
                            label="Search"
                            placeholder="Username or email"
                            value={term}
                            onChange={(event) => setTerm(event.target.value)}
                        />

                        <TextField
                            size="small"
                            select
                            fullWidth
                            label="Status"
                            value={status}
                            onChange={(event) => {
                                setStatus(event.target.value)
                                setPage(0)
                            }}
                        >
                            <MenuItem value="">Any status</MenuItem>
                            {STATUSES.map((value) => (
                                <MenuItem key={value} value={value}>
                                    {value.replace(/_/g, " ")}
                                </MenuItem>
                            ))}
                        </TextField>

                        <TextField
                            size="small"
                            select
                            fullWidth
                            label="Role"
                            value={role}
                            onChange={(event) => {
                                setRole(event.target.value)
                                setPage(0)
                            }}
                        >
                            <MenuItem value="">Any role</MenuItem>
                            {roleOptions.map((value) => (
                                <MenuItem key={value} value={value}>
                                    {value}
                                </MenuItem>
                            ))}
                        </TextField>
                    </Box>

                    {activeFilters.length > 0 && (
                        <Stack
                            direction="row"
                            sx={{ mt: 2, gap: 1, alignItems: "center", flexWrap: "wrap" }}
                        >
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                Filtering by
                            </Typography>

                            {activeFilters.map((filter) => (
                                <Chip
                                    key={filter.label}
                                    size="small"
                                    label={filter.label}
                                    onDelete={filter.clear}
                                    sx={{ maxWidth: "100%" }}
                                />
                            ))}
                        </Stack>
                    )}
                </Box>

                <Divider />

                {error !== null && (
                    <Box sx={{ p: 2 }}>
                        <ErrorAlert
                            error={error}
                            onRetry={() => {
                                setLoading(true)
                                setReloadToken((n) => n + 1)
                            }}
                        />
                    </Box>
                )}

                <TableContainer sx={{ overflowX: "auto" }}>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell>User</TableCell>
                                <TableCell>Email</TableCell>
                                <TableCell>Status</TableCell>
                                <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                                    Roles
                                </TableCell>
                                <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                                    Created
                                </TableCell>
                            </TableRow>
                        </TableHead>

                        <TableBody>
                            {loading && <TableSkeleton rows={5} columns={COLUMN_COUNT} />}

                            {!loading &&
                                users.map((user) => {
                                    const fullName =
                                        [user.firstName, user.lastName].filter(Boolean).join(" ") ||
                                        "—"
                                    const shownRoles = user.roles.slice(0, ROLE_CHIP_LIMIT)
                                    const hiddenRoles = user.roles.slice(ROLE_CHIP_LIMIT)

                                    return (
                                        <TableRow
                                            key={user.id}
                                            hover
                                            sx={{ cursor: "pointer" }}
                                            onClick={() => navigate(`/admin/users/${user.id}`)}
                                        >
                                            <TableCell>
                                                {/* A real link, not just a row click: the target has
                                                    to be focusable, announced, and openable in a new
                                                    tab. The row click stays for pointer users. */}
                                                <MuiLink
                                                    component={Link}
                                                    to={`/admin/users/${user.id}`}
                                                    onClick={(event) => event.stopPropagation()}
                                                    sx={{ fontWeight: 500, color: "text.primary" }}
                                                >
                                                    {user.username}
                                                </MuiLink>

                                                <Typography
                                                    variant="caption"
                                                    sx={{ display: "block", color: "text.secondary" }}
                                                >
                                                    {fullName}
                                                </Typography>
                                            </TableCell>

                                            <TableCell>
                                                <Stack
                                                    direction="row"
                                                    sx={{
                                                        gap: 1,
                                                        alignItems: "center",
                                                        flexWrap: "wrap",
                                                    }}
                                                >
                                                    <Box component="span" sx={{ wordBreak: "break-word" }}>
                                                        {user.email}
                                                    </Box>

                                                    {/* The pending status already says the address is
                                                        unconfirmed, so the chip only appears when the
                                                        status column is not saying it too. */}
                                                    {!user.email_verified &&
                                                        user.status !== "PENDING_EMAIL_VERIFICATION" && (
                                                            <Chip
                                                                label="unverified"
                                                                size="small"
                                                                color="warning"
                                                                variant="outlined"
                                                            />
                                                        )}
                                                </Stack>
                                            </TableCell>

                                            <TableCell>
                                                <UserStatusChip status={user.status} />
                                            </TableCell>

                                            <TableCell
                                                sx={{ display: { xs: "none", md: "table-cell" } }}
                                            >
                                                {user.roles.length === 0 ? (
                                                    <Typography
                                                        variant="caption"
                                                        sx={{ color: "text.secondary" }}
                                                    >
                                                        None
                                                    </Typography>
                                                ) : (
                                                    <Stack
                                                        direction="row"
                                                        sx={{ gap: 0.5, flexWrap: "wrap" }}
                                                    >
                                                        {shownRoles.map((name) => (
                                                            <Chip key={name} label={name} size="small" />
                                                        ))}

                                                        {hiddenRoles.length > 0 && (
                                                            <Tooltip title={hiddenRoles.join(", ")}>
                                                                <Chip
                                                                    label={`+${hiddenRoles.length}`}
                                                                    size="small"
                                                                    variant="outlined"
                                                                />
                                                            </Tooltip>
                                                        )}
                                                    </Stack>
                                                )}
                                            </TableCell>

                                            <TableCell
                                                sx={{
                                                    display: { xs: "none", md: "table-cell" },
                                                    whiteSpace: "nowrap",
                                                }}
                                            >
                                                {formatDate(user.created_at)}
                                            </TableCell>
                                        </TableRow>
                                    )
                                })}

                            {!loading && error === null && users.length === 0 && (
                                <TableStateRow columns={COLUMN_COUNT}>
                                    <EmptyState
                                        icon={PersonSearch}
                                        title={
                                            activeFilters.length > 0
                                                ? "No accounts match these filters"
                                                : "No accounts yet"
                                        }
                                        description={
                                            activeFilters.length > 0
                                                ? "Search matches usernames and email addresses exactly as stored — try a shorter term or clear a filter."
                                                : "Accounts appear here as soon as someone registers or is provisioned."
                                        }
                                        action={
                                            activeFilters.length > 0 && (
                                                <Button size="small" variant="outlined" onClick={clearAll}>
                                                    Clear filters
                                                </Button>
                                            )
                                        }
                                    />
                                </TableStateRow>
                            )}
                        </TableBody>
                    </Table>
                </TableContainer>

                <TablePagination
                    component="div"
                    count={total}
                    page={page}
                    onPageChange={(_event, next) => setPage(next)}
                    rowsPerPage={rowsPerPage}
                    onRowsPerPageChange={(event) => {
                        setRowsPerPage(Number(event.target.value))
                        setPage(0)
                    }}
                    rowsPerPageOptions={[10, 25, 50, 100]}
                />
            </Section>
        </Stack>
    )
}
