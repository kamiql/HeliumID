import {
    Box,
    Button,
    Checkbox,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Divider,
    FormControlLabel,
    Stack,
    TextField,
    Tooltip,
    Typography,
} from "@mui/material"
import { Add, Delete, Edit, Lock, Security } from "@mui/icons-material"
import { useCallback, useEffect, useState } from "react"
import PageHeader from "../../../../components/dashboard/PageHeader.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import Section from "../../../../components/ui/Section.tsx"
import { EmptyState, ListSkeleton } from "../../../../components/ui/StateView.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { Permissions, usePermissions } from "../../../../hooks/usePermissions.ts"
import { toHeliumError } from "../../../../api/problem.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { Role } from "../../../../api/types.ts"

/**
 * Seed colour for a new role's swatch.
 *
 * A role's colour is data the server stores, so it is a literal rather than a theme token —
 * but the value a user is offered first should match the current brand indigo.
 */
const DEFAULT_ROLE_COLOR = "#4F46E5"

/** Groups `resource:action` permissions by their resource prefix for a readable editor. */
function groupPermissions(permissions: string[]): Record<string, string[]> {
    const groups: Record<string, string[]> = {}
    for (const permission of permissions) {
        const [group] = permission.split(":")
        groups[group] = [...(groups[group] ?? []), permission]
    }
    return groups
}

/**
 * Why the built-in roles cannot be edited or deleted from here.
 *
 * They are referenced from code, and stripping ADMINISTRATOR's permissions would be a
 * one-click lockout — the server answers `409 conflict` for exactly that reason.
 */
const BUILT_IN_REASON =
    "Built-in roles are referenced from code. Stripping ADMINISTRATOR would lock everyone out of administration, so the server refuses to change them."

/** How many permission chips a role card shows before the rest collapse behind "+N more". */
const CHIP_LIMIT = 8

export default function AdminRolesPage() {
    const { confirm } = useConfirm()
    const permissions = usePermissions()
    const canWrite = permissions.has(Permissions.ADMIN_ROLE_WRITE)

    const [roles, setRoles] = useState<Role[]>([])
    const [catalog, setCatalog] = useState<string[]>([])
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(true)
    const [expanded, setExpanded] = useState<string[]>([])

    const [open, setOpen] = useState(false)
    const [editing, setEditing] = useState<Role | null>(null)
    const [name, setName] = useState("")
    const [description, setDescription] = useState("")
    const [color, setColor] = useState(DEFAULT_ROLE_COLOR)
    const [selected, setSelected] = useState<string[]>([])
    const [busy, setBusy] = useState(false)
    const [formError, setFormError] = useState<unknown>(null)

    // `loading` starts true and the retry button raises it again; a refresh after saving or
    // deleting a role keeps the current cards visible instead of flashing a skeleton.
    const load = useCallback(() => {
        adminApi
            .roles()
            .then(({ data }) => {
                setRoles(data)
                setError(null)
                setLoading(false)
            })
            .catch((caught: unknown) => {
                setError(caught)
                setLoading(false)
            })
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
        setColor(role?.color ?? DEFAULT_ROLE_COLOR)
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

    const toggleExpanded = (roleName: string) =>
        setExpanded((current) =>
            current.includes(roleName)
                ? current.filter((item) => item !== roleName)
                : [...current, roleName],
        )

    const toggleGroup = (entries: string[], checked: boolean) =>
        setSelected((current) =>
            checked
                ? [...current, ...entries.filter((entry) => !current.includes(entry))]
                : current.filter((entry) => !entries.includes(entry)),
        )

    return (
        <Stack spacing={3} sx={{ maxWidth: 1100, mx: "auto" }}>
            <PageHeader
                title="Roles & permissions"
                description="Roles are flat bundles of permissions — they do not inherit from one another."
                breadcrumbs={[{ label: "Admin", to: "/admin" }]}
                actions={
                    canWrite && (
                        <Button variant="contained" startIcon={<Add />} onClick={() => openEditor(null)}>
                            New role
                        </Button>
                    )
                }
            />

            {error !== null && (
                <ErrorAlert
                    error={error}
                    onRetry={() => {
                        setLoading(true)
                        setError(null)
                        load()
                    }}
                />
            )}

            {loading && (
                <Section title="Roles" description="Loading the role catalogue.">
                    <ListSkeleton rows={4} />
                </Section>
            )}

            {!loading && roles.length === 0 && error === null && (
                <Section title="Roles" disableBodyPadding>
                    <EmptyState
                        icon={Security}
                        title="No roles defined"
                        description="Create a role to bundle permissions and assign them to accounts in one step."
                        action={
                            canWrite && (
                                <Button
                                    variant="contained"
                                    startIcon={<Add />}
                                    onClick={() => openEditor(null)}
                                >
                                    New role
                                </Button>
                            )
                        }
                    />
                </Section>
            )}

            {!loading && roles.length > 0 && (
                <Box
                    sx={{
                        display: "grid",
                        gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" },
                        gap: 2,
                    }}
                >
                    {roles.map((role) => {
                        const isExpanded = expanded.includes(role.name)
                        const shown = isExpanded
                            ? role.permissions
                            : role.permissions.slice(0, CHIP_LIMIT)
                        const hidden = role.permissions.length - shown.length

                        return (
                            <Section
                                key={role.name}
                                headingLevel="h2"
                                title={role.name}
                                description={role.description || "No description."}
                                banner={
                                    <Stack
                                        direction="row"
                                        sx={{ gap: 1, alignItems: "center", flexWrap: "wrap" }}
                                    >
                                        {/* The swatch is the role's own colour, straight from the
                                            API — the one place a literal colour value belongs. */}
                                        <Box
                                            aria-hidden
                                            sx={{
                                                width: 12,
                                                height: 12,
                                                borderRadius: "50%",
                                                backgroundColor: role.color,
                                            }}
                                        />

                                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                            {role.permissions.length}{" "}
                                            {role.permissions.length === 1
                                                ? "permission"
                                                : "permissions"}
                                        </Typography>

                                        {role.built_in && (
                                            <Tooltip title={BUILT_IN_REASON}>
                                                <Chip
                                                    icon={<Lock fontSize="small" />}
                                                    label="built-in"
                                                    size="small"
                                                    variant="outlined"
                                                />
                                            </Tooltip>
                                        )}
                                    </Stack>
                                }
                                actions={
                                    <Tooltip title={role.built_in ? BUILT_IN_REASON : ""}>
                                        <Stack direction="row" sx={{ gap: 0.5 }}>
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
                                    </Tooltip>
                                }
                            >
                                {role.permissions.length === 0 ? (
                                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                        No permissions granted — holding this role gives no access
                                        beyond a plain account.
                                    </Typography>
                                ) : (
                                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                        {shown.map((permission) => (
                                            <Chip key={permission} label={permission} size="small" />
                                        ))}

                                        {hidden > 0 && (
                                            <Chip
                                                label={`+${hidden} more`}
                                                size="small"
                                                variant="outlined"
                                                onClick={() => toggleExpanded(role.name)}
                                                aria-expanded={false}
                                                aria-label={`Show all ${role.permissions.length} permissions of ${role.name}`}
                                            />
                                        )}

                                        {isExpanded && role.permissions.length > CHIP_LIMIT && (
                                            <Chip
                                                label="Show fewer"
                                                size="small"
                                                variant="outlined"
                                                onClick={() => toggleExpanded(role.name)}
                                                aria-expanded
                                                aria-label={`Collapse the permissions of ${role.name}`}
                                            />
                                        )}
                                    </Box>
                                )}
                            </Section>
                        )
                    })}
                </Box>
            )}

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
                            helperText={
                                editing !== null
                                    ? "A role's name is its identity — create a new role to rename one."
                                    : "Uppercase identifier, e.g. SUPPORT."
                            }
                        />

                        <TextField
                            fullWidth
                            size="small"
                            label="Description"
                            value={description}
                            onChange={(event) => setDescription(event.target.value)}
                            helperText="Shown wherever the role is listed. Say who should hold it."
                        />

                        <TextField
                            size="small"
                            type="color"
                            label="Colour"
                            value={color}
                            onChange={(event) => setColor(event.target.value)}
                            helperText="Only a label swatch — it grants nothing."
                            sx={{ width: 160 }}
                        />

                        <Box>
                            <Stack
                                direction="row"
                                sx={{
                                    gap: 1,
                                    alignItems: "baseline",
                                    justifyContent: "space-between",
                                }}
                            >
                                <Typography variant="subtitle2" component="h3">
                                    Permissions
                                </Typography>

                                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                    {selected.length} of {catalog.length} selected
                                </Typography>
                            </Stack>

                            <Stack sx={{ mt: 1.5, gap: 1.5 }} divider={<Divider flexItem />}>
                                {Object.entries(groups).map(([group, entries]) => {
                                    const chosen = entries.filter((entry) =>
                                        selected.includes(entry),
                                    ).length
                                    const allChosen = chosen === entries.length

                                    return (
                                        <Box key={group}>
                                            <FormControlLabel
                                                control={
                                                    <Checkbox
                                                        size="small"
                                                        checked={allChosen}
                                                        indeterminate={chosen > 0 && !allChosen}
                                                        onChange={(event) =>
                                                            toggleGroup(entries, event.target.checked)
                                                        }
                                                    />
                                                }
                                                label={
                                                    <Typography
                                                        variant="subtitle2"
                                                        sx={{ textTransform: "uppercase" }}
                                                    >
                                                        {group}{" "}
                                                        <Box
                                                            component="span"
                                                            sx={{
                                                                color: "text.secondary",
                                                                fontWeight: 400,
                                                                textTransform: "none",
                                                            }}
                                                        >
                                                            ({chosen}/{entries.length})
                                                        </Box>
                                                    </Typography>
                                                }
                                            />

                                            <Box
                                                sx={{
                                                    display: "grid",
                                                    gridTemplateColumns: {
                                                        xs: "1fr",
                                                        sm: "repeat(2, minmax(0, 1fr))",
                                                    },
                                                    pl: 3.5,
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
                                                                                  (item) =>
                                                                                      item !==
                                                                                      permission,
                                                                              ),
                                                                    )
                                                                }
                                                            />
                                                        }
                                                        label={
                                                            <Typography variant="body2">
                                                                {permission}
                                                            </Typography>
                                                        }
                                                    />
                                                ))}
                                            </Box>
                                        </Box>
                                    )
                                })}
                            </Stack>
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
