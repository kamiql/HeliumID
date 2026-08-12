import {
    Box,
    Card,
    Chip,
    Collapse,
    IconButton,
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
import { KeyboardArrowDown, KeyboardArrowUp } from "@mui/icons-material"
import { Fragment, useEffect, useState } from "react"
import { Link } from "react-router"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { formatDateTime, humanize } from "../../../../lib/format.ts"
import type { AuditRecord } from "../../../../api/types.ts"

export default function AdminAuditPage() {
    const [eventType, setEventType] = useState("")
    const [userId, setUserId] = useState("")
    const [debounced, setDebounced] = useState({ eventType: "", userId: "" })
    const [page, setPage] = useState(0)
    const [rowsPerPage, setRowsPerPage] = useState(50)

    const [records, setRecords] = useState<AuditRecord[]>([])
    const [total, setTotal] = useState(0)
    const [expanded, setExpanded] = useState<string | null>(null)
    const [error, setError] = useState<unknown>(null)

    useEffect(() => {
        const handle = window.setTimeout(() => {
            setDebounced({ eventType: eventType.trim(), userId: userId.trim() })
            setPage(0)
        }, 300)
        return () => window.clearTimeout(handle)
    }, [eventType, userId])

    useEffect(() => {
        let active = true

        adminApi
            .audit({
                event_type: debounced.eventType || undefined,
                user_id: debounced.userId || undefined,
                limit: rowsPerPage,
                offset: page * rowsPerPage,
            })
            .then(({ data }) => {
                if (!active) return
                setRecords(data.items)
                setTotal(data.total)
                setError(null)
            })
            .catch((caught: unknown) => {
                if (active) setError(caught)
            })

        return () => {
            active = false
        }
    }, [debounced, page, rowsPerPage])

    return (
        <Stack spacing={3} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title="Audit log"
                description="Security events recorded by the identity server."
            />

            <Card>
                <Box sx={{ p: 2 }}>
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                        <TextField
                            size="small"
                            fullWidth
                            label="Event type"
                            placeholder="e.g. LOGIN_SUCCEEDED"
                            value={eventType}
                            onChange={(event) => setEventType(event.target.value)}
                        />

                        <TextField
                            size="small"
                            fullWidth
                            label="Subject user ID"
                            placeholder="UUID"
                            value={userId}
                            onChange={(event) => setUserId(event.target.value)}
                        />
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
                                <TableCell width={40} />
                                <TableCell>When</TableCell>
                                <TableCell>Event</TableCell>
                                <TableCell>Outcome</TableCell>
                                <TableCell>Actor</TableCell>
                                <TableCell>Subject</TableCell>
                                <TableCell>Client</TableCell>
                            </TableRow>
                        </TableHead>

                        <TableBody>
                            {records.map((record) => {
                                const open = expanded === record.id
                                const metadata = Object.entries(record.metadata)

                                return (
                                    <Fragment key={record.id}>
                                        <TableRow hover>
                                            <TableCell>
                                                <IconButton
                                                    size="small"
                                                    onClick={() => setExpanded(open ? null : record.id)}
                                                >
                                                    {open ? (
                                                        <KeyboardArrowUp fontSize="small" />
                                                    ) : (
                                                        <KeyboardArrowDown fontSize="small" />
                                                    )}
                                                </IconButton>
                                            </TableCell>

                                            <TableCell sx={{ whiteSpace: "nowrap" }}>
                                                {formatDateTime(record.created_at)}
                                            </TableCell>

                                            <TableCell>{humanize(record.event_type)}</TableCell>

                                            <TableCell>
                                                <Chip
                                                    size="small"
                                                    variant="outlined"
                                                    label={record.outcome.toLowerCase()}
                                                    color={
                                                        record.outcome.toUpperCase() === "SUCCESS"
                                                            ? "success"
                                                            : "error"
                                                    }
                                                />
                                            </TableCell>

                                            <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                                                {record.actor_user_id ?? "—"}
                                            </TableCell>

                                            <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                                                {record.subject_user_id ? (
                                                    <Link to={`/admin/users/${record.subject_user_id}`}>
                                                        {record.subject_user_id}
                                                    </Link>
                                                ) : (
                                                    "—"
                                                )}
                                            </TableCell>

                                            <TableCell>{record.client_id ?? "—"}</TableCell>
                                        </TableRow>

                                        <TableRow>
                                            <TableCell colSpan={7} sx={{ py: 0, borderBottom: open ? undefined : "none" }}>
                                                <Collapse in={open} unmountOnExit>
                                                    <Box sx={{ py: 2 }}>
                                                        <Typography
                                                            variant="caption"
                                                            sx={{ color: "text.secondary" }}
                                                        >
                                                            Request {record.request_id}
                                                        </Typography>

                                                        {metadata.length === 0 ? (
                                                            <Typography variant="body2">
                                                                No metadata recorded.
                                                            </Typography>
                                                        ) : (
                                                            <Box
                                                                sx={{
                                                                    mt: 1,
                                                                    display: "grid",
                                                                    gridTemplateColumns: {
                                                                        xs: "1fr",
                                                                        sm: "auto 1fr",
                                                                    },
                                                                    columnGap: 2,
                                                                    rowGap: 0.5,
                                                                }}
                                                            >
                                                                {metadata.map(([key, value]) => (
                                                                    <Fragment key={key}>
                                                                        <Typography
                                                                            variant="body2"
                                                                            sx={{ fontWeight: 600 }}
                                                                        >
                                                                            {key}
                                                                        </Typography>
                                                                        <Typography
                                                                            variant="body2"
                                                                            sx={{ wordBreak: "break-all" }}
                                                                        >
                                                                            {value}
                                                                        </Typography>
                                                                    </Fragment>
                                                                ))}
                                                            </Box>
                                                        )}
                                                    </Box>
                                                </Collapse>
                                            </TableCell>
                                        </TableRow>
                                    </Fragment>
                                )
                            })}

                            {records.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={7}>
                                        <Typography variant="body2" sx={{ color: "text.secondary", py: 2 }}>
                                            No audit records matched.
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
                    rowsPerPageOptions={[25, 50, 100, 200]}
                />
            </Card>
        </Stack>
    )
}
