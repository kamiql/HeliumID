import {
    Alert,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Stack,
    TextField,
    Typography,
} from "@mui/material"
import { CheckCircleOutlined, FingerprintOutlined, ShieldOutlined } from "@mui/icons-material"
import { useEffect, useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { ACCOUNT_ANCHORS } from "../../../../components/dashboard/account/AccountRequirement.tsx"
import { EmptyState, ListSkeleton } from "../../../../components/ui/StateView.tsx"
import PasswordField from "../../../../components/PasswordField.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import OneTimeSecretDialog from "../../../../components/OneTimeSecretDialog.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { useAuthStore } from "../../../../stores/auth.store.ts"
import { accountApi } from "../../../../api/account.ts"
import { describeError, ErrorCode, toHeliumError } from "../../../../api/problem.ts"
import { createWebauthnCredential, webauthnUnavailable } from "../../../../lib/webauthn.ts"
import { formatDateTime, formatRelative } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { MfaFactor } from "../../../../api/types.ts"

/**
 * Passkeys and security keys registered as a second factor.
 *
 * Registration is two calls around one browser ceremony: the server reserves a `PENDING` factor
 * and hands out a challenge, the authenticator signs it, and the attestation goes back against
 * the same `factor_id`. An abandoned ceremony simply leaves the pending factor unconfirmed —
 * nothing here is enabled by the client's say-so.
 *
 * The private key never leaves the authenticator, so there is nothing on this page to save, back
 * up or copy. The one exception is the recovery-code set the server returns when a passkey is
 * what turned two-factor on, which is shown once and never again.
 */
export default function PasskeysBox() {
    const user = useUser()
    const refresh = useAuthStore((state) => state.refresh)

    const [factors, setFactors] = useState<MfaFactor[]>([])
    const [factorsLoading, setFactorsLoading] = useState(true)
    const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)

    const [addOpen, setAddOpen] = useState(false)
    const [label, setLabel] = useState("")

    const [removing, setRemoving] = useState<MfaFactor | null>(null)
    const [password, setPassword] = useState("")

    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<unknown>(null)

    // Registration is offered even without a passkey present, so the unsupported case has to be
    // answered before the button is drawn rather than after it is pressed.
    const unavailable = webauthnUnavailable()

    const passkeys = factors.filter(
        (factor) => factor.type === "webauthn" && factor.status === "ACTIVE",
    )

    // No `setFactorsLoading(true)` here: the flag starts true for the first fetch, and a
    // refresh after adding or removing a key should update the list in place rather than
    // replace it with a skeleton.
    const loadFactors = () => {
        accountApi
            .factors()
            .then(({ data }) => setFactors(data))
            .catch(() => setFactors([]))
            .finally(() => setFactorsLoading(false))
    }

    useEffect(loadFactors, [])

    const handleAdd = async () => {
        if (loading) return

        const trimmed = label.trim()

        try {
            setLoading(true)
            setError(null)

            const { data } = await accountApi.enrollWebauthn({ label: trimmed || null })
            // Straight into the ceremony: the browser only honours it while the click that
            // started it still counts as user activation.
            const registration = await createWebauthnCredential(data.options)

            const confirmed = await accountApi.confirmWebauthn({
                factor_id: data.factor_id,
                label: trimmed || null,
                ...registration,
            })

            setAddOpen(false)
            setLabel("")
            loadFactors()
            void refresh()

            // Recovery codes come back exactly once, and only when this key is what enabled
            // two-factor authentication. The field is absent otherwise, never an empty list.
            if (confirmed.data.recovery_codes?.length) {
                setRecoveryCodes(confirmed.data.recovery_codes)
            } else {
                notify("Passkey added.", "success")
            }
        } catch (caught) {
            const heliumError = toHeliumError(caught)

            // Closing the browser's prompt is the user changing their mind. The dialog stays
            // open so they can try again; nothing needs to be reported.
            if (heliumError.is(ErrorCode.WEBAUTHN_CANCELLED)) return

            setError(heliumError)
        } finally {
            setLoading(false)
        }
    }

    const handleRemove = async () => {
        if (!removing) return

        try {
            setLoading(true)
            setError(null)

            await accountApi.removeWebauthn({
                factor_id: removing.id,
                current_password: password || null,
            })

            setRemoving(null)
            setPassword("")
            loadFactors()
            void refresh()
            notify("Passkey removed.", "warning")
        } catch (caught) {
            setError(toHeliumError(caught))
        } finally {
            setLoading(false)
        }
    }

    return (
        <>
            <AccountBox
                id={ACCOUNT_ANCHORS.passkeys}
                title="Passkeys & security keys"
                description="Confirm sign-ins with a key held by your device instead of a typed code."
                requirements={[
                    {
                        id: "email",
                        label: "Verify your email address first",
                        hint: "Passkey setup relies on an address we can reach if you lose the device.",
                        fix: { label: "Go to email address", anchor: ACCOUNT_ANCHORS.email },
                        satisfied: user.email_verified || user.mfa_enabled,
                    },
                ]}
                banner={
                    <Chip
                        size="small"
                        variant="outlined"
                        color={passkeys.length > 0 ? "success" : "default"}
                        icon={passkeys.length > 0 ? <CheckCircleOutlined /> : <ShieldOutlined />}
                        label={
                            passkeys.length === 1
                                ? "1 registered"
                                : `${passkeys.length} registered`
                        }
                    />
                }
                actions={
                    <AccountButton
                        variant={passkeys.length > 0 ? "outlined" : "contained"}
                        aria-label="Add a passkey"
                        disabled={loading || factorsLoading || unavailable !== null}
                        onClick={() => {
                            setError(null)
                            setLabel("")
                            setAddOpen(true)
                        }}
                    >
                        Add passkey
                    </AccountButton>
                }
            >
                <Stack sx={{ gap: 2 }}>
                    {unavailable !== null && (
                        // Nothing has gone wrong — this browser simply cannot run the ceremony.
                        <Alert severity="info">{describeError(unavailable)}</Alert>
                    )}

                    {error !== null && !addOpen && removing === null && (
                        <ErrorAlert error={error} />
                    )}

                    {factorsLoading ? (
                        <ListSkeleton rows={2} />
                    ) : passkeys.length === 0 ? (
                        <EmptyState
                            dense
                            icon={FingerprintOutlined}
                            title="No passkeys yet"
                            description="A passkey lets you finish a sign-in with a fingerprint, a face scan or a hardware key. There is nothing to type, and nothing a phishing site can capture."
                        />
                    ) : (
                        <List disablePadding>
                            {passkeys.map((passkey) => (
                                <ListItem
                                    key={passkey.id}
                                    disableGutters
                                    divider
                                    sx={{
                                        py: 1.5,
                                        pr: { xs: 11.5, sm: 12.5 },
                                        alignItems: "flex-start",
                                    }}
                                    secondaryAction={
                                        <AccountButton
                                            variant="outlined"
                                            size="small"
                                            color="error"
                                            disabled={loading}
                                            aria-label={`Remove passkey ${passkey.label || "Security key"}`}
                                            onClick={() => {
                                                setError(null)
                                                setPassword("")
                                                setRemoving(passkey)
                                            }}
                                        >
                                            Remove
                                        </AccountButton>
                                    }
                                >
                                    <ListItemIcon sx={{ mt: 0.5 }}>
                                        <FingerprintOutlined />
                                    </ListItemIcon>

                                    <ListItemText
                                        primary={passkey.label || "Security key"}
                                        secondary={`Added ${formatDateTime(passkey.created_at)} · ${
                                            passkey.last_used_at
                                                ? `last used ${formatRelative(passkey.last_used_at)}`
                                                : "never used"
                                        }`}
                                        sx={{ my: 0, wordBreak: "break-word" }}
                                    />
                                </ListItem>
                            ))}
                        </List>
                    )}
                </Stack>
            </AccountBox>

            <Dialog
                open={addOpen}
                onClose={() => {
                    if (loading) return
                    setAddOpen(false)
                    setError(null)
                }}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Add a passkey</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Name this key so you can tell it apart later, then confirm with your
                            device. The key itself stays on the device — we only ever see its
                            public half.
                        </Typography>

                        <TextField
                            fullWidth
                            autoFocus
                            label="Name"
                            placeholder="Work laptop"
                            helperText="Optional. Anything that reminds you which device this is."
                            value={label}
                            slotProps={{ htmlInput: { maxLength: 64 } }}
                            onChange={(event) => {
                                setLabel(event.target.value)
                                setError(null)
                            }}
                            onKeyDown={(event) => {
                                if (event.key === "Enter") void handleAdd()
                            }}
                        />

                        {error !== null && <ErrorAlert error={error} />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <AccountButton onClick={() => setAddOpen(false)} disabled={loading}>
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        onClick={() => void handleAdd()}
                        disabled={loading}
                    >
                        Continue
                    </AccountButton>
                </DialogActions>
            </Dialog>

            <Dialog
                open={removing !== null}
                onClose={() => {
                    if (loading) return
                    setRemoving(null)
                    setError(null)
                }}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Remove this passkey?</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <Alert severity="warning">
                            {removing?.label || "This key"} will no longer sign you in.
                            {passkeys.length === 1
                                ? " It is your last passkey, so make sure another second factor still works."
                                : ""}
                        </Alert>

                        <PasswordField
                            fullWidth
                            autoFocus
                            label="Current password"
                            autoComplete="current-password"
                            value={password}
                            onType={(value) => {
                                setPassword(value)
                                setError(null)
                            }}
                        />

                        {error !== null && <ErrorAlert error={error} />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <AccountButton onClick={() => setRemoving(null)} disabled={loading}>
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        color="error"
                        onClick={() => void handleRemove()}
                        disabled={loading}
                    >
                        Remove
                    </AccountButton>
                </DialogActions>
            </Dialog>

            <OneTimeSecretDialog
                open={recoveryCodes !== null}
                title="Save your recovery codes"
                description="Each code signs you in once if you lose the device holding your passkey. Store them somewhere other than that device."
                values={recoveryCodes ?? []}
                downloadFileName="helium-recovery-codes.txt"
                onClose={() => {
                    setRecoveryCodes(null)
                    notify("Two-factor authentication enabled.", "success")
                }}
            />
        </>
    )
}
