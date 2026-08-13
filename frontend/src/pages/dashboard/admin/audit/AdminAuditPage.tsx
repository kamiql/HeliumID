import {
    Box,
    Button,
    Chip,
    Collapse,
    Divider,
    IconButton,
    Link as MuiLink,
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
import { KeyboardArrowDown, KeyboardArrowUp, ManageSearch } from "@mui/icons-material"
import { Fragment, useEffect, useState } from "react"
import { Link } from "react-router"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import DefinitionList from "../../../../components/ui/DefinitionList.tsx"
import Section from "../../../../components/ui/Section.tsx"
import { EmptyState, TableSkeleton, TableStateRow } from "../../../../components/ui/StateView.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { formatDateTime, humanize } from "../../../../lib/format.ts"
import { MONO_FONT } from "../../../../lib/theme.ts"
import type { AuditRecord } from "../../../../api/types.ts"

/** Hidden columns keep their cells, so the expansion row's `colSpan` never has to change. */
const COLUMN_COUNT = 7

/** Enough of a UUID to tell two rows apart, without a column of unreadable hex. */
function shorten(id: string): string {
    return id.length > 12 ? `${id.slice(0, 8)}…` : id
}

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
    const [loading, setLoading] = useState(true)
    // Bumped by the retry button so the effect re-runs with the identical query.
    const [reloadToken, setReloadToken] = useState(0)

    useEffect(() => {
        const handle = window.setTimeout(() => {
            setDebounced({ eventType: eventType.trim(), userId: userId.trim() })
            setPage(0)
        }, 300)
        return () => window.clearTimeout(handle)
    }, [eventType, userId])

    useEffect(() => {
        let active = true

        // `loading` starts true and the retry button raises it again. Not raising it on every
        // filter change is deliberate: the rows stay readable while a new query runs, and the
        // app shell's progress bar carries the in-flight signal.
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
    }, [debounced, page, rowsPerPage, reloadToken])

    const filtered = eventType.trim().length > 0 || userId.trim().length > 0

    const clearAll = () => {
        setEventType("")
        setUserId("")
    }

    return (
        <Stack spacing={3} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title="Audit log"
                description="Security events recorded by the identity server."
                breadcrumbs={[{ label: "Admin", to: "/admin" }]}
                meta={
                    !loading &&
                    error === null && (
                        <Chip
                            size="small"
                            variant="outlined"
                            label={`${total} ${total === 1 ? "event" : "events"}`}
                        />
                    )
                }
            />

            <Section
                title="Events"
                description="Newest first. Expand a row for its request ID and recorded metadata."
                disableBodyPadding
                actions={
                    filtered && (
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
                            gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))" },
                            gap: 2,
                        }}
                    >
                        <TextField
                            size="small"
                            fullWidth
                            label="Event type"
                            placeholder="LOGIN_SUCCEEDED"
                            value={eventType}
                            onChange={(event) => setEventType(event.target.value)}
                            helperText="Exact event name in upper snake case, e.g. LOGIN_SUCCEEDED or MFA_CHALLENGE_FAILED."
                        />

                        <TextField
                            size="small"
                            fullWidth
                            label="Subject user ID"
                            placeholder="6f1c2e5a-8b4d-4f2e-9a10-7c3d5e8b1f04"
                            value={userId}
                            onChange={(event) => setUserId(event.target.value)}
                            helperText="The account the event was about, as a UUID. Copy it from the user's detail page."
                            sx={{ "& input": { fontFamily: MONO_FONT } }}
                        />
                    </Box>
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
                                <TableCell width={48} />
                                <TableCell>When</TableCell>
                                <TableCell>Event</TableCell>
                                <TableCell>Outcome</TableCell>
                                <TableCell sx={{ display: { xs: "none", lg: "table-cell" } }}>
                                    Actor
                                </TableCell>
                                <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                                    Subject
                                </TableCell>
                                <TableCell sx={{ display: { xs: "none", lg: "table-cell" } }}>
                                    Client
                                </TableCell>
                            </TableRow>
                        </TableHead>

                        <TableBody>
                            {loading && <TableSkeleton rows={6} columns={COLUMN_COUNT} />}

                            {!loading &&
                                records.map((record) => {
                                    const open = expanded === record.id
                                    const metadata = Object.entries(record.metadata)

                                    return (
                                        <Fragment key={record.id}>
                                            <TableRow hover>
                                                <TableCell>
                                                    <IconButton
                                                        size="small"
                                                        aria-label={
                                                            open
                                                                ? `Hide details of ${humanize(record.event_type)}`
                                                                : `Show details of ${humanize(record.event_type)}`
                                                        }
                                                        aria-expanded={open}
                                                        onClick={() =>
                                                            setExpanded(open ? null : record.id)
                                                        }
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

                                                <TableCell
                                                    sx={{
                                                        display: { xs: "none", lg: "table-cell" },
                                                        fontFamily: MONO_FONT,
                                                        fontSize: "0.75rem",
                                                        whiteSpace: "nowrap",
                                                    }}
                                                >
                                                    {record.actor_user_id ? (
                                                        <Tooltip title={record.actor_user_id}>
                                                            <Box component="span" tabIndex={0}>
                                                                {shorten(record.actor_user_id)}
                                                            </Box>
                                                        </Tooltip>
                                                    ) : (
                                                        "—"
                                                    )}
                                                </TableCell>

                                                <TableCell
                                                    sx={{
                                                        display: { xs: "none", md: "table-cell" },
                                                        fontFamily: MONO_FONT,
                                                        fontSize: "0.75rem",
                                                        whiteSpace: "nowrap",
                                                    }}
                                                >
                                                    {record.subject_user_id ? (
                                                        <Tooltip title={record.subject_user_id}>
                                                            <MuiLink
                                                                component={Link}
                                                                to={`/admin/users/${record.subject_user_id}`}
                                                                sx={{ fontFamily: MONO_FONT }}
                                                            >
                                                                {shorten(record.subject_user_id)}
                                                            </MuiLink>
                                                        </Tooltip>
                                                    ) : (
                                                        "—"
                                                    )}
                                                </TableCell>

                                                <TableCell
                                                    sx={{
                                                        display: { xs: "none", lg: "table-cell" },
                                                        whiteSpace: "nowrap",
                                                    }}
                                                >
                                                    {record.client_id ?? "—"}
                                                </TableCell>
                                            </TableRow>

                                            <TableRow>
                                                <TableCell
                                                    colSpan={COLUMN_COUNT}
                                                    sx={{
                                                        py: 0,
                                                        borderBottom: open ? undefined : "none",
                                                    }}
                                                >
                                                    <Collapse in={open} unmountOnExit>
                                                        <Box sx={{ py: 2 }}>
                                                            <DefinitionList
                                                                columns={2}
                                                                items={[
                                                                    {
                                                                        label: "Request ID",
                                                                        value: record.request_id,
                                                                        mono: true,
                                                                    },
                                                                    {
                                                                        label: "Actor",
                                                                        value:
                                                                            record.actor_user_id ??
                                                                            "System",
                                                                        mono: Boolean(
                                                                            record.actor_user_id,
                                                                        ),
                                                                    },
                                                                    {
                                                                        label: "Subject",
                                                                        value:
                                                                            record.subject_user_id ??
                                                                            "—",
                                                                        mono: Boolean(
                                                                            record.subject_user_id,
                                                                        ),
                                                                    },
                                                                    {
                                                                        label: "Client",
                                                                        value: record.client_id ?? "—",
                                                                        mono: Boolean(record.client_id),
                                                                    },
                                                                ]}
                                                            />

                                                            <Typography
                                                                variant="subtitle2"
                                                                component="h3"
                                                                sx={{ mt: 3 }}
                                                            >
                                                                Metadata
                                                            </Typography>

                                                            {metadata.length === 0 ? (
                                                                <Typography
                                                                    variant="body2"
                                                                    sx={{
                                                                        mt: 0.5,
                                                                        color: "text.secondary",
                                                                    }}
                                                                >
                                                                    No metadata recorded for this
                                                                    event.
                                                                </Typography>
                                                            ) : (
                                                                <DefinitionList
                                                                    sx={{ mt: 1.5 }}
                                                                    columns={2}
                                                                    items={metadata.map(
                                                                        ([key, value]) => ({
                                                                            label: humanize(key),
                                                                            value,
                                                                            mono: true,
                                                                        }),
                                                                    )}
                                                                />
                                                            )}
                                                        </Box>
                                                    </Collapse>
                                                </TableCell>
                                            </TableRow>
                                        </Fragment>
                                    )
                                })}

                            {!loading && error === null && records.length === 0 && (
                                <TableStateRow columns={COLUMN_COUNT}>
                                    <EmptyState
                                        icon={ManageSearch}
                                        title={
                                            filtered
                                                ? "No events match these filters"
                                                : "No audit events recorded"
                                        }
                                        description={
                                            filtered
                                                ? "Event type is matched exactly, and the subject must be a full user ID — a partial UUID will never match."
                                                : "Security events appear here as soon as the server records one."
                                        }
                                        action={
                                            filtered && (
                                                <Button
                                                    size="small"
                                                    variant="outlined"
                                                    onClick={clearAll}
                                                >
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
                    rowsPerPageOptions={[25, 50, 100, 200]}
                />
            </Section>
        </Stack>
    )
}
