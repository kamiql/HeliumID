import {
    Box,
    Button,
    Chip,
    Divider,
    IconButton,
    ListItemIcon,
    ListItemText,
    Menu,
    MenuItem,
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
import {
    Add,
    Apps,
    Autorenew,
    Delete,
    Edit,
    MoreVert,
    ToggleOff,
    ToggleOn,
} from "@mui/icons-material"
import { useCallback, useEffect, useState } from "react"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import OneTimeSecretDialog from "../../../../components/OneTimeSecretDialog.tsx"
import Section from "../../../../components/ui/Section.tsx"
import { EmptyState, TableSkeleton, TableStateRow } from "../../../../components/ui/StateView.tsx"
import ClientFormDialog from "./ClientFormDialog.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { Permissions, usePermissions } from "../../../../hooks/usePermissions.ts"
import { formatDate } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import { MONO_FONT } from "../../../../lib/theme.ts"
import type { ClientSecret, OAuthClient } from "../../../../api/types.ts"

/** Columns are hidden with CSS rather than unmounted, so `colSpan` never has to change. */
const COLUMN_COUNT = 6

export default function AdminClientsPage() {
    const { confirm } = useConfirm()
    const permissions = usePermissions()
    const canWrite = permissions.has(Permissions.ADMIN_CLIENT_WRITE)

    const [clients, setClients] = useState<OAuthClient[]>([])
    const [total, setTotal] = useState(0)
    const [page, setPage] = useState(0)
    const [rowsPerPage, setRowsPerPage] = useState(25)
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(true)

    const [formOpen, setFormOpen] = useState(false)
    const [editing, setEditing] = useState<OAuthClient | null>(null)
    const [issuedSecret, setIssuedSecret] = useState<ClientSecret | null>(null)

    const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null)
    const [menuClient, setMenuClient] = useState<OAuthClient | null>(null)

    const load = useCallback(() => {
        // `loading` starts true and the retry button raises it again; a refresh after a
        // mutation keeps the current rows visible instead of flashing a skeleton.
        adminApi
            .clients(rowsPerPage, page * rowsPerPage)
            .then(({ data }) => {
                setClients(data.items)
                setTotal(data.total)
                setError(null)
                setLoading(false)
            })
            .catch((caught: unknown) => {
                setError(caught)
                setLoading(false)
            })
    }, [page, rowsPerPage])

    useEffect(load, [load])

    const closeMenu = () => {
        setMenuAnchor(null)
        setMenuClient(null)
    }

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

    const registerButton = (
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

    return (
        <Stack spacing={3} sx={{ maxWidth: 1200, mx: "auto" }}>
            <PageHeader
                title="OAuth applications"
                description="Relying parties allowed to authenticate users against this server."
                breadcrumbs={[{ label: "Admin", to: "/admin" }]}
                meta={
                    !loading &&
                    error === null && (
                        <Chip
                            size="small"
                            variant="outlined"
                            label={`${total} ${total === 1 ? "application" : "applications"}`}
                        />
                    )
                }
                actions={canWrite && registerButton}
            />

            <Section
                title="Registered applications"
                description="Redirect URIs are matched exactly at the authorization endpoint — open one to review them."
                disableBodyPadding
            >
                {error !== null && (
                    <>
                        <Box sx={{ p: 2 }}>
                            <ErrorAlert
                                error={error}
                                onRetry={() => {
                                    setLoading(true)
                                    setError(null)
                                    load()
                                }}
                            />
                        </Box>
                        <Divider />
                    </>
                )}

                <TableContainer sx={{ overflowX: "auto" }}>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell>Application</TableCell>
                                <TableCell>Type</TableCell>
                                <TableCell sx={{ display: { xs: "none", lg: "table-cell" } }}>
                                    Scopes
                                </TableCell>
                                <TableCell>Status</TableCell>
                                <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                                    Created
                                </TableCell>
                                <TableCell align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>

                        <TableBody>
                            {loading && <TableSkeleton rows={4} columns={COLUMN_COUNT} />}

                            {!loading &&
                                clients.map((client) => (
                                    <TableRow key={client.client_id} hover>
                                        <TableCell sx={{ maxWidth: 320 }}>
                                            <Typography sx={{ fontWeight: 500 }}>
                                                {client.name}
                                            </Typography>

                                            <Typography
                                                variant="caption"
                                                sx={{
                                                    display: "block",
                                                    color: "text.secondary",
                                                    fontFamily: MONO_FONT,
                                                    wordBreak: "break-all",
                                                }}
                                            >
                                                {client.client_id}
                                            </Typography>

                                            {/* The full redirect-URI list used to be the widest
                                                thing on the page; it lives in the edit dialog now
                                                and only its shape is summarised here. */}
                                            <Tooltip
                                                title={
                                                    client.redirect_uris.length === 0 ? (
                                                        "No redirect URI registered — the authorization endpoint will reject every request from this client."
                                                    ) : (
                                                        <Box
                                                            component="ul"
                                                            sx={{
                                                                m: 0,
                                                                pl: 2,
                                                                fontFamily: MONO_FONT,
                                                                wordBreak: "break-all",
                                                            }}
                                                        >
                                                            {client.redirect_uris.map((uri) => (
                                                                <li key={uri}>{uri}</li>
                                                            ))}
                                                        </Box>
                                                    )
                                                }
                                            >
                                                <Box
                                                    component="span"
                                                    tabIndex={0}
                                                    sx={{
                                                        display: "inline-block",
                                                        mt: 0.5,
                                                        fontSize: "0.75rem",
                                                        color:
                                                            client.redirect_uris.length === 0
                                                                ? "error.main"
                                                                : "text.secondary",
                                                        borderBottom: "1px dotted",
                                                        borderColor: "divider",
                                                    }}
                                                >
                                                    {client.redirect_uris.length === 0
                                                        ? "No redirect URI"
                                                        : `${client.redirect_uris.length} redirect URI${
                                                              client.redirect_uris.length === 1
                                                                  ? ""
                                                                  : "s"
                                                          }`}
                                                </Box>
                                            </Tooltip>
                                        </TableCell>

                                        <TableCell>
                                            <Stack sx={{ gap: 0.5 }}>
                                                <Chip
                                                    label={client.type.toLowerCase()}
                                                    size="small"
                                                    color={
                                                        client.type === "CONFIDENTIAL"
                                                            ? "secondary"
                                                            : "default"
                                                    }
                                                    variant="outlined"
                                                    sx={{
                                                        textTransform: "capitalize",
                                                        width: "fit-content",
                                                    }}
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

                                        <TableCell
                                            sx={{
                                                display: { xs: "none", lg: "table-cell" },
                                                maxWidth: 220,
                                            }}
                                        >
                                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                                {client.scopes.map((scope) => (
                                                    <Chip key={scope} label={scope} size="small" />
                                                ))}

                                                {client.scopes.length === 0 && (
                                                    <Typography
                                                        variant="caption"
                                                        sx={{ color: "text.secondary" }}
                                                    >
                                                        None
                                                    </Typography>
                                                )}
                                            </Box>
                                        </TableCell>

                                        <TableCell>
                                            <Stack sx={{ gap: 0.5 }}>
                                                <Chip
                                                    label={client.enabled ? "enabled" : "disabled"}
                                                    size="small"
                                                    color={client.enabled ? "success" : "default"}
                                                    variant="outlined"
                                                    sx={{ width: "fit-content" }}
                                                />

                                                {client.skip_consent && (
                                                    <Tooltip title="Users are never shown the consent screen for this application.">
                                                        <Chip
                                                            label="skips consent"
                                                            size="small"
                                                            color="warning"
                                                            variant="outlined"
                                                            sx={{ width: "fit-content" }}
                                                        />
                                                    </Tooltip>
                                                )}
                                            </Stack>
                                        </TableCell>

                                        <TableCell
                                            sx={{
                                                display: { xs: "none", md: "table-cell" },
                                                whiteSpace: "nowrap",
                                            }}
                                        >
                                            {formatDate(client.created_at)}
                                        </TableCell>

                                        <TableCell align="right">
                                            <Stack
                                                direction="row"
                                                sx={{ gap: 0.5, justifyContent: "flex-end" }}
                                            >
                                                <Tooltip title={`Edit ${client.name}`}>
                                                    <span>
                                                        <IconButton
                                                            size="small"
                                                            aria-label={`Edit ${client.name}`}
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

                                                <Tooltip title={`More actions for ${client.name}`}>
                                                    <span>
                                                        <IconButton
                                                            size="small"
                                                            aria-label={`More actions for ${client.name}`}
                                                            aria-haspopup="menu"
                                                            aria-expanded={
                                                                menuClient?.client_id ===
                                                                client.client_id
                                                            }
                                                            disabled={!canWrite}
                                                            onClick={(event) => {
                                                                setMenuAnchor(event.currentTarget)
                                                                setMenuClient(client)
                                                            }}
                                                        >
                                                            <MoreVert fontSize="small" />
                                                        </IconButton>
                                                    </span>
                                                </Tooltip>
                                            </Stack>
                                        </TableCell>
                                    </TableRow>
                                ))}

                            {!loading && error === null && clients.length === 0 && (
                                <TableStateRow columns={COLUMN_COUNT}>
                                    <EmptyState
                                        icon={Apps}
                                        title="No applications registered yet"
                                        description="A relying party has to be registered here before it can send users to the authorization endpoint."
                                        action={canWrite && registerButton}
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

            <Menu
                open={menuAnchor !== null && menuClient !== null}
                anchorEl={menuAnchor}
                onClose={closeMenu}
                anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                transformOrigin={{ vertical: "top", horizontal: "right" }}
            >
                <MenuItem
                    disabled={!canWrite || !menuClient}
                    onClick={() => {
                        const client = menuClient
                        closeMenu()
                        if (client) void handleToggle(client)
                    }}
                >
                    <ListItemIcon>
                        {menuClient?.enabled ? (
                            <ToggleOff fontSize="small" />
                        ) : (
                            <ToggleOn fontSize="small" />
                        )}
                    </ListItemIcon>
                    <ListItemText
                        primary={menuClient?.enabled ? "Disable application" : "Enable application"}
                        secondary={
                            menuClient?.enabled
                                ? "Stops new authorizations"
                                : "Allows authorizations again"
                        }
                    />
                </MenuItem>

                <MenuItem
                    // Destructive: the current secret dies the moment this runs, so it is
                    // marked as such here as well as in the confirmation.
                    disabled={!canWrite || menuClient?.type !== "CONFIDENTIAL"}
                    onClick={() => {
                        const client = menuClient
                        closeMenu()
                        if (client) void handleRotate(client)
                    }}
                    sx={{ color: "error.main" }}
                >
                    <ListItemIcon sx={{ color: "inherit" }}>
                        <Autorenew fontSize="small" />
                    </ListItemIcon>
                    <ListItemText
                        primary="Rotate secret"
                        secondary={
                            menuClient?.type === "CONFIDENTIAL"
                                ? "Invalidates the current secret"
                                : "Public clients have no secret"
                        }
                        slotProps={{ secondary: { sx: { color: "text.secondary" } } }}
                    />
                </MenuItem>

                <Divider sx={{ my: 0.5 }} />

                <MenuItem
                    disabled={!canWrite || !menuClient}
                    onClick={() => {
                        const client = menuClient
                        closeMenu()
                        if (client) void handleDelete(client)
                    }}
                    sx={{ color: "error.main" }}
                >
                    <ListItemIcon sx={{ color: "inherit" }}>
                        <Delete fontSize="small" />
                    </ListItemIcon>
                    <ListItemText
                        primary="Delete application"
                        secondary="Existing tokens and consents stop working"
                        slotProps={{ secondary: { sx: { color: "text.secondary" } } }}
                    />
                </MenuItem>
            </Menu>

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
