import {
    Box,
    Button,
    Card,
    CardContent,
    Checkbox,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    FormControlLabel,
    Stack,
    TextField,
    Typography,
} from "@mui/material"
import { Add, Delete, Edit, Lock } from "@mui/icons-material"
import { useCallback, useEffect, useState } from "react"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { Permissions, usePermissions } from "../../../../hooks/usePermissions.ts"
import { toHeliumError } from "../../../../api/problem.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { Role } from "../../../../api/types.ts"

/** Groups `resource:action` permissions by their resource prefix for a readable editor. */
function groupPermissions(permissions: string[]): Record<string, string[]> {
    const groups: Record<string, string[]> = {}
    for (const permission of permissions) {
        const [group] = permission.split(":")
        groups[group] = [...(groups[group] ?? []), permission]
    }
    return groups
}

export default function AdminRolesPage() {
    const { confirm } = useConfirm()
    const permissions = usePermissions()
    const canWrite = permissions.has(Permissions.ADMIN_ROLE_WRITE)

    const [roles, setRoles] = useState<Role[]>([])
    const [catalog, setCatalog] = useState<string[]>([])
    const [error, setError] = useState<unknown>(null)

    const [open, setOpen] = useState(false)
    const [editing, setEditing] = useState<Role | null>(null)
    const [name, setName] = useState("")
    const [description, setDescription] = useState("")
    const [color, setColor] = useState("#5865F2")
    const [selected, setSelected] = useState<string[]>([])
    const [busy, setBusy] = useState(false)
    const [formError, setFormError] = useState<unknown>(null)

    const load = useCallback(() => {
        adminApi
            .roles()
            .then(({ data }) => {
                setRoles(data)
                setError(null)
            })
            .catch((caught: unknown) => setError(caught))
    }, [])

    useEffect(() => {
        load()
        adminApi
            .permissions()
            .then(({ data }) => setCatalog(data))
            .catch(() => setCatalog([]))
    }, [load])

    const openEditor = (role: Role | null) => {
        setEditing(role)
        setName(role?.name ?? "")
        setDescription(role?.description ?? "")
        setColor(role?.color ?? "#5865F2")
        setSelected(role?.permissions ?? [])
        setFormError(null)
        setOpen(true)
    }

    const handleSave = async () => {
        try {
            setBusy(true)
            setFormError(null)

            await adminApi.upsertRole(name.trim(), {
                name: name.trim(),
                description,
                color,
                permissions: selected,
            })

            setOpen(false)
            load()
            notify("Role saved.", "success")
        } catch (caught) {
            // A built-in role answers 409: it is referenced from code, and stripping
            // ADMINISTRATOR's permissions would be a one-click lockout.
            setFormError(toHeliumError(caught))
        } finally {
            setBusy(false)
        }
    }

    const handleDelete = async (role: Role) => {
        const confirmed = await confirm({
            title: `Delete role ${role.name}?`,
            message: "Users holding this role lose the permissions it granted.",
            confirmText: "Delete role",
        })
        if (!confirmed) return

        try {
            await adminApi.deleteRole(role.name)
            load()
            notify("Role deleted.", "success")
        } catch (caught) {
            setError(caught)
        }
    }

    const groups = groupPermissions(catalog)

    return (
        <Stack spacing={3} sx={{ maxWidth: 1100, mx: "auto" }}>
            <PageHeader
                title="Roles & permissions"
                description="Roles are flat bundles of permissions — they do not inherit from one another."
                actions={
                    canWrite && (
                        <Button variant="contained" startIcon={<Add />} onClick={() => openEditor(null)}>
                            New role
                        </Button>
                    )
                }
            />

            {error !== null && <ErrorAlert error={error} />}

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", md: "repeat(2, 1fr)" },
                    gap: 2,
                }}
            >
                {roles.map((role) => (
                    <Card key={role.name}>
                        <CardContent>
                            <Stack spacing={2}>
                                <Stack
                                    direction="row"
                                    sx={{ alignItems: "center", justifyContent: "space-between", gap: 1 }}
                                >
                                    <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                                        <Box
                                            sx={{
                                                width: 12,
                                                height: 12,
                                                borderRadius: "50%",
                                                backgroundColor: role.color,
                                            }}
                                        />

                                        <Typography variant="h6" sx={{ fontWeight: 600 }}>
                                            {role.name}
                                        </Typography>

                                        {role.built_in && (
                                            <Chip
                                                icon={<Lock fontSize="small" />}
                                                label="built-in"
                                                size="small"
                                                variant="outlined"
                                            />
                                        )}
                                    </Stack>

                                    <Stack direction="row" spacing={0.5}>
                                        <Button
                                            size="small"
                                            startIcon={<Edit />}
                                            disabled={!canWrite || role.built_in}
                                            onClick={() => openEditor(role)}
                                        >
                                            Edit
                                        </Button>

                                        <Button
                                            size="small"
                                            color="error"
                                            startIcon={<Delete />}
                                            disabled={!canWrite || role.built_in}
                                            onClick={() => void handleDelete(role)}
                                        >
                                            Delete
                                        </Button>
                                    </Stack>
                                </Stack>

                                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                    {role.description || "No description."}
                                </Typography>

                                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                    {role.permissions.map((permission) => (
                                        <Chip key={permission} label={permission} size="small" />
                                    ))}

                                    {role.permissions.length === 0 && (
                                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                            No permissions granted.
                                        </Typography>
                                    )}
                                </Box>
                            </Stack>
                        </CardContent>
                    </Card>
                ))}
            </Box>

            <Dialog
                open={open}
                onClose={() => (busy ? undefined : setOpen(false))}
                fullWidth
                maxWidth="sm"
            >
                <DialogTitle>{editing ? `Edit ${editing.name}` : "New role"}</DialogTitle>

                <DialogContent>
                    <Stack spacing={2.5} sx={{ mt: 1 }}>
                        <TextField
                            fullWidth
                            size="small"
                            label="Name"
                            value={name}
                            disabled={editing !== null}
                            onChange={(event) => setName(event.target.value.toUpperCase())}
                            helperText="Uppercase identifier, e.g. SUPPORT."
                        />

                        <TextField
                            fullWidth
                            size="small"
                            label="Description"
                            value={description}
                            onChange={(event) => setDescription(event.target.value)}
                        />

                        <TextField
                            size="small"
                            type="color"
                            label="Colour"
                            value={color}
                            onChange={(event) => setColor(event.target.value)}
                            sx={{ width: 140 }}
                        />

                        <Box>
                            <Typography variant="subtitle2" sx={{ mb: 1 }}>
                                Permissions
                            </Typography>

                            {Object.entries(groups).map(([group, entries]) => (
                                <Box key={group} sx={{ mb: 1.5 }}>
                                    <Typography
                                        variant="caption"
                                        sx={{ color: "text.secondary", textTransform: "uppercase" }}
                                    >
                                        {group}
                                    </Typography>

                                    <Box
                                        sx={{
                                            display: "grid",
                                            gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" },
                                        }}
                                    >
                                        {entries.map((permission) => (
                                            <FormControlLabel
                                                key={permission}
                                                control={
                                                    <Checkbox
                                                        size="small"
                                                        checked={selected.includes(permission)}
                                                        onChange={(event) =>
                                                            setSelected((current) =>
                                                                event.target.checked
                                                                    ? [...current, permission]
                                                                    : current.filter(
                                                                          (item) => item !== permission,
                                                                      ),
                                                            )
                                                        }
                                                    />
                                                }
                                                label={
                                                    <Typography variant="body2">{permission}</Typography>
                                                }
                                            />
                                        ))}
                                    </Box>
                                </Box>
                            ))}
                        </Box>

                        {formError !== null && <ErrorAlert error={formError} />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <Button onClick={() => setOpen(false)} disabled={busy}>
                        Cancel
                    </Button>

                    <Button
                        variant="contained"
                        onClick={() => void handleSave()}
                        disabled={busy || name.trim().length === 0}
                    >
                        Save role
                    </Button>
                </DialogActions>
            </Dialog>
        </Stack>
    )
}
