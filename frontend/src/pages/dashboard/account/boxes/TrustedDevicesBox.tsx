import { List, ListItem, ListItemIcon, ListItemText, Stack } from "@mui/material"
import { PhonelinkLock } from "@mui/icons-material"
import { useEffect, useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { EmptyState, ListSkeleton } from "../../../../components/ui/StateView.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { accountApi } from "../../../../api/account.ts"
import { formatDateTime, formatRelative } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { TrustedDevice } from "../../../../api/types.ts"

/**
 * Devices allowed to skip the second factor until they expire.
 *
 * Trust is granted at the MFA prompt and cannot be withdrawn from there, so this list is the
 * only way back: a device that is lost or no longer yours has to be revoked here.
 */
export default function TrustedDevicesBox() {
    const { confirm } = useConfirm()

    const [devices, setDevices] = useState<TrustedDevice[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<unknown>(null)
    const [busy, setBusy] = useState<string | null>(null)
    const [revokingAll, setRevokingAll] = useState(false)

    // No `setLoading(true)` here: `loading` starts true for the first fetch, and a refresh
    // after a revoke should update the list in place rather than replace it with a skeleton.
    // The global progress bar in the app shell already signals the in-flight request.
    const load = () => {
        accountApi
            .trustedDevices()
            .then(({ data }) => {
                setDevices(data)
                setError(null)
            })
            .catch((caught: unknown) => setError(caught))
            .finally(() => setLoading(false))
    }

    useEffect(load, [])

    /** Explicit retry from the error alert: here the skeleton is the feedback. */
    const reload = () => {
        setLoading(true)
        setError(null)
        load()
    }

    const handleRevoke = async (device: TrustedDevice) => {
        const confirmed = await confirm({
            title: "Revoke trusted device?",
            message: "It will have to pass two-factor authentication again at the next sign-in.",
            confirmText: "Revoke",
        })

        if (!confirmed) return

        try {
            setBusy(device.id)
            setError(null)
            await accountApi.revokeTrustedDevice(device.id)
            load()
            notify("Trusted device revoked.", "success")
        } catch (caught) {
            setError(caught)
        } finally {
            setBusy(null)
        }
    }

    const handleRevokeAll = async () => {
        const confirmed = await confirm({
            title: "Revoke all trusted devices?",
            message:
                "Every device is forgotten, this one included — you will be asked for a code the next time you sign in here.",
            confirmText: "Revoke all",
        })

        if (!confirmed) return

        try {
            setRevokingAll(true)
            setError(null)
            const { data } = await accountApi.revokeAllTrustedDevices()
            load()
            notify(`Revoked ${data.revoked} trusted device(s), including this one.`, "success")
        } catch (caught) {
            setError(caught)
        } finally {
            setRevokingAll(false)
        }
    }

    const showSkeleton = loading && devices.length === 0

    return (
        <AccountBox
            title="Trusted devices"
            description="Devices that skip the two-factor prompt when you sign in."
            actions={
                devices.length > 0 ? (
                    <AccountButton
                        variant="outlined"
                        color="error"
                        disabled={revokingAll || busy !== null}
                        aria-label="Revoke all trusted devices"
                        onClick={() => void handleRevokeAll()}
                    >
                        Revoke all
                    </AccountButton>
                ) : undefined
            }
        >
            <Stack sx={{ gap: 2 }}>
                {error !== null && <ErrorAlert error={error} onRetry={reload} />}

                {showSkeleton ? (
                    <ListSkeleton rows={2} />
                ) : devices.length === 0 ? (
                    <EmptyState
                        dense
                        icon={PhonelinkLock}
                        title="No trusted devices"
                        description="You will be asked for a code every time you sign in. Choosing “remember this device” at the two-factor prompt adds one here."
                    />
                ) : (
                    <List disablePadding>
                        {devices.map((device) => {
                            const label = device.label ?? "Unknown device"

                            return (
                                <ListItem
                                    key={device.id}
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
                                            disabled={busy === device.id || revokingAll}
                                            aria-label={`Revoke trusted device ${label}`}
                                            onClick={() => void handleRevoke(device)}
                                        >
                                            Revoke
                                        </AccountButton>
                                    }
                                >
                                    <ListItemIcon sx={{ mt: 0.5 }}>
                                        <PhonelinkLock />
                                    </ListItemIcon>

                                    <ListItemText
                                        primary={label}
                                        secondary={`Last used ${formatRelative(device.last_used_at)} · trusted since ${formatDateTime(device.created_at)} · expires ${formatRelative(device.expires_at)}`}
                                        sx={{ my: 0, wordBreak: "break-word" }}
                                    />
                                </ListItem>
                            )
                        })}
                    </List>
                )}
            </Stack>
        </AccountBox>
    )
}
