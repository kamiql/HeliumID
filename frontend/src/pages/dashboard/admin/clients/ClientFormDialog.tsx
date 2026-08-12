import {
    Alert,
    Box,
    Button,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    FormControl,
    FormControlLabel,
    FormLabel,
    InputLabel,
    MenuItem,
    OutlinedInput,
    Radio,
    RadioGroup,
    Select,
    Stack,
    Switch,
    TextField,
} from "@mui/material"
import { useEffect, useState } from "react"
import StringListField from "../../../../components/StringListField.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { adminApi } from "../../../../api/admin.ts"
import { describeFieldError, toHeliumError } from "../../../../api/problem.ts"
import type {
    ClientSecret,
    ClientType,
    GrantType,
    OAuthClient,
    Scope,
} from "../../../../api/types.ts"

/**
 * `password` and `implicit` are deliberately absent and must stay absent — the backend enum
 * does not contain them either (`GrantType.FORBIDDEN_WIRE_VALUES`).
 */
const GRANT_TYPES: GrantType[] = ["authorization_code", "refresh_token", "client_credentials"]

type ClientFormDialogProps = {
    open: boolean
    /** `null` registers a new client; otherwise the dialog edits that client. */
    client: OAuthClient | null
    onClose: () => void
    onSaved: () => void
    /** Called with the plaintext secret returned by registration — shown once, then gone. */
    onSecretIssued: (secret: ClientSecret) => void
}

export default function ClientFormDialog(props: ClientFormDialogProps) {
    if (!props.open) return null

    // Keyed on the subject so every open starts from that client's values, without an effect
    // that copies props into state.
    return <ClientForm key={props.client?.client_id ?? "new"} {...props} />
}

function ClientForm({ open, client, onClose, onSaved, onSecretIssued }: ClientFormDialogProps) {
    const editing = client !== null

    const [scopeCatalog, setScopeCatalog] = useState<Scope[]>([])
    const [clientId, setClientId] = useState(client?.client_id ?? "")
    const [name, setName] = useState(client?.name ?? "")
    const [type, setType] = useState<ClientType>(
        client?.type === "CONFIDENTIAL" ? "CONFIDENTIAL" : "PUBLIC",
    )
    const [redirectUris, setRedirectUris] = useState<string[]>(client?.redirect_uris ?? [])
    const [scopes, setScopes] = useState<string[]>(client?.scopes ?? ["openid", "profile", "email"])
    const [grantTypes, setGrantTypes] = useState<GrantType[]>(
        client
            ? client.grant_types.filter((grant): grant is GrantType =>
                  (GRANT_TYPES as string[]).includes(grant),
              )
            : ["authorization_code", "refresh_token"],
    )
    const [audiences, setAudiences] = useState<string[]>(client?.audiences ?? [])
    const [skipConsent, setSkipConsent] = useState(client?.skip_consent ?? false)
    const [enabled, setEnabled] = useState(client?.enabled ?? true)

    const [error, setError] = useState<unknown>(null)
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
    const [busy, setBusy] = useState(false)

    useEffect(() => {
        adminApi
            .scopes()
            .then(({ data }) => setScopeCatalog(data))
            .catch(() => setScopeCatalog([]))
    }, [])

    const handleSave = async () => {
        try {
            setBusy(true)
            setError(null)
            setFieldErrors({})

            if (editing && client) {
                await adminApi.updateClient(client.client_id, {
                    name,
                    redirect_uris: redirectUris,
                    scopes,
                    grant_types: grantTypes,
                    audiences,
                    skip_consent: skipConsent,
                    enabled,
                })
            } else {
                const { data } = await adminApi.registerClient({
                    client_id: clientId.trim(),
                    name,
                    type,
                    redirect_uris: redirectUris,
                    scopes,
                    grant_types: grantTypes,
                    audiences,
                    skip_consent: skipConsent,
                })
                if (data.secret) onSecretIssued(data)
            }

            onSaved()
            onClose()
        } catch (caught) {
            const heliumError = toHeliumError(caught)
            setFieldErrors(heliumError.fieldErrors)
            setError(heliumError)
        } finally {
            setBusy(false)
        }
    }

    const valid =
        name.trim().length > 0 &&
        (editing || clientId.trim().length > 0) &&
        redirectUris.length > 0 &&
        grantTypes.length > 0

    return (
        <Dialog open={open} onClose={() => (busy ? undefined : onClose())} fullWidth maxWidth="sm">
            <DialogTitle>{editing ? `Edit ${client?.name}` : "Register application"}</DialogTitle>

            <DialogContent>
                <Stack spacing={2.5} sx={{ mt: 1 }}>
                    <TextField
                        fullWidth
                        size="small"
                        label="Client ID"
                        value={clientId}
                        disabled={editing}
                        onChange={(event) => setClientId(event.target.value)}
                        error={Boolean(fieldErrors.client_id)}
                        helperText={
                            fieldErrors.client_id
                                ? describeFieldError(fieldErrors.client_id)
                                : "Stable identifier the application uses at the token endpoint."
                        }
                    />

                    <TextField
                        fullWidth
                        size="small"
                        label="Display name"
                        value={name}
                        onChange={(event) => setName(event.target.value)}
                        error={Boolean(fieldErrors.name)}
                        helperText={
                            fieldErrors.name
                                ? describeFieldError(fieldErrors.name)
                                : "Shown to users on the consent screen."
                        }
                    />

                    <FormControl disabled={editing}>
                        <FormLabel>Client type</FormLabel>
                        <RadioGroup
                            row
                            value={type}
                            onChange={(event) => setType(event.target.value as ClientType)}
                        >
                            <FormControlLabel
                                value="PUBLIC"
                                control={<Radio />}
                                label="Public (SPA / native — PKCE only)"
                            />
                            <FormControlLabel
                                value="CONFIDENTIAL"
                                control={<Radio />}
                                label="Confidential (server-side, holds a secret)"
                            />
                        </RadioGroup>
                    </FormControl>

                    {!editing && type === "CONFIDENTIAL" && (
                        <Alert severity="info">
                            A client secret is generated on registration and shown once. It is
                            stored as a hash and cannot be recovered — only rotated.
                        </Alert>
                    )}

                    <StringListField
                        label="Redirect URI"
                        values={redirectUris}
                        onChange={setRedirectUris}
                        placeholder="https://app.example.com/callback"
                        error={Boolean(fieldErrors.redirect_uris)}
                        helperText="Matched exactly — no wildcards, no trailing-slash tolerance. Press Enter to add."
                    />

                    <FormControl fullWidth size="small">
                        <InputLabel id="client-scopes-label">Scopes</InputLabel>
                        <Select
                            labelId="client-scopes-label"
                            multiple
                            value={scopes}
                            input={<OutlinedInput label="Scopes" />}
                            onChange={(event) =>
                                setScopes(
                                    typeof event.target.value === "string"
                                        ? event.target.value.split(",")
                                        : event.target.value,
                                )
                            }
                            renderValue={(selected) => (
                                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                    {selected.map((scope) => (
                                        <Chip key={scope} label={scope} size="small" />
                                    ))}
                                </Box>
                            )}
                        >
                            {scopeCatalog.map((scope) => (
                                <MenuItem key={scope.name} value={scope.name}>
                                    {scope.name} — {scope.description}
                                </MenuItem>
                            ))}
                        </Select>
                    </FormControl>

                    <FormControl fullWidth size="small">
                        <InputLabel id="client-grants-label">Grant types</InputLabel>
                        <Select
                            labelId="client-grants-label"
                            multiple
                            value={grantTypes}
                            input={<OutlinedInput label="Grant types" />}
                            onChange={(event) =>
                                setGrantTypes(
                                    (typeof event.target.value === "string"
                                        ? event.target.value.split(",")
                                        : event.target.value) as GrantType[],
                                )
                            }
                            renderValue={(selected) => (
                                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                    {selected.map((grant) => (
                                        <Chip key={grant} label={grant} size="small" />
                                    ))}
                                </Box>
                            )}
                        >
                            {GRANT_TYPES.map((grant) => (
                                <MenuItem key={grant} value={grant}>
                                    {grant}
                                </MenuItem>
                            ))}
                        </Select>
                    </FormControl>

                    <StringListField
                        label="Audience"
                        values={audiences}
                        onChange={setAudiences}
                        placeholder="https://api.example.com"
                        helperText="Audience values placed in access tokens issued to this client."
                    />

                    <FormControlLabel
                        control={
                            <Switch
                                checked={skipConsent}
                                onChange={(event) => setSkipConsent(event.target.checked)}
                            />
                        }
                        label="Skip consent screen (first-party applications only)"
                    />

                    {editing && (
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={enabled}
                                    onChange={(event) => setEnabled(event.target.checked)}
                                />
                            }
                            label="Enabled"
                        />
                    )}

                    {error !== null && <ErrorAlert error={error} />}
                </Stack>
            </DialogContent>

            <DialogActions>
                <Button onClick={onClose} disabled={busy}>
                    Cancel
                </Button>

                <Button variant="contained" onClick={() => void handleSave()} disabled={busy || !valid}>
                    {editing ? "Save changes" : "Register"}
                </Button>
            </DialogActions>
        </Dialog>
    )
}
