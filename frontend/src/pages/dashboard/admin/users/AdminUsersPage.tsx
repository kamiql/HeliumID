import {
    Box,
    Card,
    Chip,
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
    Typography,
} from "@mui/material"
import { useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
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
            })
            .catch((caught: unknown) => {
                if (active) setError(caught)
            })

        return () => {
            active = false
        }
    }, [debouncedTerm, status, role, page, rowsPerPage])

    const roleOptions = useMemo(() => roles.map((entry) => entry.name), [roles])

    return (
        <Stack spacing={3} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader title="Users" description="Search and administer accounts." />

            <Card>
                <Box sx={{ p: 2 }}>
                    <Stack
                        direction={{ xs: "column", sm: "row" }}
                        spacing={2}
                        sx={{ alignItems: "stretch" }}
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
                            label="Status"
                            value={status}
                            onChange={(event) => {
                                setStatus(event.target.value)
                                setPage(0)
                            }}
                            sx={{ minWidth: 220 }}
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
                            label="Role"
                            value={role}
                            onChange={(event) => {
                                setRole(event.target.value)
                                setPage(0)
                            }}
                            sx={{ minWidth: 200 }}
                        >
                            <MenuItem value="">Any role</MenuItem>
                            {roleOptions.map((value) => (
                                <MenuItem key={value} value={value}>
                                    {value}
                                </MenuItem>
                            ))}
                        </TextField>
                    </Stack>
                </Box>

                {error !== null && (
                    <Box sx={{ px: 2, pb: 2 }}>
                        <ErrorAlert error={error} />
                    </Box>
                )}

                <TableContainer>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell>User</TableCell>
                                <TableCell>Email</TableCell>
                                <TableCell>Status</TableCell>
                                <TableCell>Roles</TableCell>
                                <TableCell>Created</TableCell>
                            </TableRow>
                        </TableHead>

                        <TableBody>
                            {users.map((user) => (
                                <TableRow
                                    key={user.id}
                                    hover
                                    sx={{ cursor: "pointer" }}
                                    onClick={() => navigate(`/admin/users/${user.id}`)}
                                >
                                    <TableCell>
                                        <Typography sx={{ fontWeight: 500 }}>
                                            {user.username}
                                        </Typography>
                                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                            {[user.firstName, user.lastName]
                                                .filter(Boolean)
                                                .join(" ") || "—"}
                                        </Typography>
                                    </TableCell>

                                    <TableCell>
                                        <Stack
                                            direction="row"
                                            spacing={1}
                                            sx={{ alignItems: "center" }}
                                        >
                                            <span>{user.email}</span>
                                            {!user.email_verified && (
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

                                    <TableCell>
                                        <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                                            {user.roles.map((name) => (
                                                <Chip key={name} label={name} size="small" />
                                            ))}
                                        </Stack>
                                    </TableCell>

                                    <TableCell>{formatDate(user.created_at)}</TableCell>
                                </TableRow>
                            ))}

                            {users.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={5}>
                                        <Typography
                                            variant="body2"
                                            sx={{ color: "text.secondary", py: 2 }}
                                        >
                                            No users matched.
                                        </Typography>
                                    </TableCell>
                                </TableRow>
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
            </Card>
        </Stack>
    )
}
