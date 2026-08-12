import {
    Box,
    Button,
    Card,
    Chip,
    IconButton,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TablePagination,
    TableRow,
    Tooltip,
    Typography,
} from "@mui/material"
import { Add, Autorenew, Delete, Edit } from "@mui/icons-material"
import { useCallback, useEffect, useState } from "react"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import OneTimeSecretDialog from "../../../../components/OneTimeSecretDialog.tsx"
import ClientFormDialog from "./ClientFormDialog.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { Permissions, usePermissions } from "../../../../hooks/usePermissions.ts"
import { formatDate } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { ClientSecret, OAuthClient } from "../../../../api/types.ts"

export default function AdminClientsPage() {
    const { confirm } = useConfirm()
    const permissions = usePermissions()
    const canWrite = permissions.has(Permissions.ADMIN_CLIENT_WRITE)

    const [clients, setClients] = useState<OAuthClient[]>([])
    const [total, setTotal] = useState(0)
    const [page, setPage] = useState(0)
    const [rowsPerPage, setRowsPerPage] = useState(25)
    const [error, setError] = useState<unknown>(null)

    const [formOpen, setFormOpen] = useState(false)
    const [editing, setEditing] = useState<OAuthClient | null>(null)
    const [issuedSecret, setIssuedSecret] = useState<ClientSecret | null>(null)

    const load = useCallback(() => {
        adminApi
            .clients(rowsPerPage, page * rowsPerPage)
            .then(({ data }) => {
                setClients(data.items)
                setTotal(data.total)
                setError(null)
            })
            .catch((caught: unknown) => setError(caught))
    }, [page, rowsPerPage])

    useEffect(load, [load])

    const handleRotate = async (client: OAuthClient) => {
        const confirmed = await confirm({
            title: `Rotate secret for ${client.name}?`,
            message:
                "The current secret stops working immediately. The new one is shown once and cannot be recovered.",
            confirmText: "Rotate secret",
        })
        if (!confirmed) return

        try {
            const { data } = await adminApi.rotateClientSecret(client.client_id)
            load()
            if (data.secret) {
                setIssuedSecret(data)
            } else {
                notify("This is a public client — it has no secret.", "info")
            }
        } catch (caught) {
            setError(caught)
        }
    }

    const handleToggle = async (client: OAuthClient) => {
        try {
            await adminApi.updateClient(client.client_id, { enabled: !client.enabled })
            load()
            notify(client.enabled ? "Application disabled." : "Application enabled.", "success")
        } catch (caught) {
            setError(caught)
        }
    }

    const handleDelete = async (client: OAuthClient) => {
        const confirmed = await confirm({
            title: `Delete ${client.name}?`,
            message: "Existing tokens and consents for this application stop working.",
            confirmText: "Delete",
        })
        if (!confirmed) return

        try {
            await adminApi.deleteClient(client.client_id)
            load()
            notify("Application deleted.", "success")
        } catch (caught) {
            setError(caught)
        }
    }

    return (
        <Stack spacing={3} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title="OAuth applications"
                description="Relying parties allowed to authenticate users against this server."
                actions={
                    canWrite && (
                        <Button
                            variant="contained"
                            startIcon={<Add />}
                            onClick={() => {
                                setEditing(null)
                                setFormOpen(true)
                            }}
                        >
                            Register application
                        </Button>
                    )
                }
            />

            {error !== null && <ErrorAlert error={error} />}

            <Card>
                <TableContainer>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell>Application</TableCell>
                                <TableCell>Type</TableCell>
                                <TableCell>Redirect URIs</TableCell>
                                <TableCell>Scopes</TableCell>
                                <TableCell>Status</TableCell>
                                <TableCell>Created</TableCell>
                                <TableCell align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>

                        <TableBody>
                            {clients.map((client) => (
                                <TableRow key={client.client_id} hover>
                                    <TableCell>
                                        <Typography sx={{ fontWeight: 500 }}>{client.name}</Typography>
                                        <Typography
                                            variant="caption"
                                            sx={{ color: "text.secondary", fontFamily: "monospace" }}
                                        >
                                            {client.client_id}
                                        </Typography>
                                    </TableCell>

                                    <TableCell>
                                        <Stack spacing={0.5}>
                                            <Chip
                                                label={client.type.toLowerCase()}
                                                size="small"
                                                color={
                                                    client.type === "CONFIDENTIAL" ? "secondary" : "default"
                                                }
                                                variant="outlined"
                                                sx={{ textTransform: "capitalize", width: "fit-content" }}
                                            />
                                            {client.has_secret && (
                                                <Typography
                                                    variant="caption"
                                                    sx={{ color: "text.secondary" }}
                                                >
                                                    secret set
                                                </Typography>
                                            )}
                                        </Stack>
                                    </TableCell>

                                    <TableCell sx={{ maxWidth: 260 }}>
                                        <Typography
                                            variant="caption"
                                            sx={{ color: "text.secondary", wordBreak: "break-all" }}
                                        >
                                            {client.redirect_uris.join(", ") || "—"}
                                        </Typography>
                                    </TableCell>

                                    <TableCell>
                                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                            {client.scopes.map((scope) => (
                                                <Chip key={scope} label={scope} size="small" />
                                            ))}
                                        </Box>
                                    </TableCell>

                                    <TableCell>
                                        <Stack spacing={0.5}>
                                            <Chip
                                                label={client.enabled ? "enabled" : "disabled"}
                                                size="small"
                                                color={client.enabled ? "success" : "default"}
                                                variant="outlined"
                                                sx={{ width: "fit-content" }}
                                            />
                                            {client.skip_consent && (
                                                <Chip
                                                    label="skips consent"
                                                    size="small"
                                                    color="warning"
                                                    variant="outlined"
                                                    sx={{ width: "fit-content" }}
                                                />
                                            )}
                                        </Stack>
                                    </TableCell>

                                    <TableCell>{formatDate(client.created_at)}</TableCell>

                                    <TableCell align="right">
                                        <Stack direction="row" spacing={0.5} sx={{ justifyContent: "flex-end" }}>
                                            <Tooltip title="Edit">
                                                <span>
                                                    <IconButton
                                                        size="small"
                                                        disabled={!canWrite}
                                                        onClick={() => {
                                                            setEditing(client)
                                                            setFormOpen(true)
                                                        }}
                                                    >
                                                        <Edit fontSize="small" />
                                                    </IconButton>
                                                </span>
                                            </Tooltip>

                                            <Tooltip title="Rotate secret">
                                                <span>
                                                    <IconButton
                                                        size="small"
                                                        disabled={!canWrite || client.type !== "CONFIDENTIAL"}
                                                        onClick={() => void handleRotate(client)}
                                                    >
                                                        <Autorenew fontSize="small" />
                                                    </IconButton>
                                                </span>
                                            </Tooltip>

                                            <Button
                                                size="small"
                                                disabled={!canWrite}
                                                onClick={() => void handleToggle(client)}
                                            >
                                                {client.enabled ? "Disable" : "Enable"}
                                            </Button>

                                            <Tooltip title="Delete">
                                                <span>
                                                    <IconButton
                                                        size="small"
                                                        color="error"
                                                        disabled={!canWrite}
                                                        onClick={() => void handleDelete(client)}
                                                    >
                                                        <Delete fontSize="small" />
                                                    </IconButton>
                                                </span>
                                            </Tooltip>
                                        </Stack>
                                    </TableCell>
                                </TableRow>
                            ))}

                            {clients.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={7}>
                                        <Typography variant="body2" sx={{ color: "text.secondary", py: 2 }}>
                                            No applications registered yet.
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

            <ClientFormDialog
                open={formOpen}
                client={editing}
                onClose={() => setFormOpen(false)}
                onSaved={load}
                onSecretIssued={setIssuedSecret}
            />

            <OneTimeSecretDialog
                open={issuedSecret !== null}
                title="Client secret"
                description={`Configure ${issuedSecret?.client_id ?? "this application"} with this secret now.`}
                values={issuedSecret?.secret ? [issuedSecret.secret] : []}
                downloadFileName={`${issuedSecret?.client_id ?? "client"}-secret.txt`}
                onClose={() => setIssuedSecret(null)}
            />
        </Stack>
    )
}
