import { Box, Chip, List, ListItem, ListItemIcon, ListItemText, Stack } from "@mui/material"
import { Devices, DevicesOther, RadioButtonChecked } from "@mui/icons-material"
import { useEffect, useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { EmptyState, ListSkeleton } from "../../../../components/ui/StateView.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { accountApi } from "../../../../api/account.ts"
import { formatDateTime, formatRelative } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { SessionInfo } from "../../../../api/types.ts"

/** Active sessions, with the one making this request marked so it is not revoked by accident. */
export default function SessionsBox() {
    const { confirm } = useConfirm()

    const [sessions, setSessions] = useState<SessionInfo[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<unknown>(null)
    const [busy, setBusy] = useState<string | null>(null)

    // No `setLoading(true)` here: `loading` starts true for the first fetch, and a refresh
    // after a revoke should update the list in place rather than replace it with a skeleton.
    // The global progress bar in the app shell already signals the in-flight request.
    const load = () => {
        accountApi
            .sessions()
            .then(({ data }) => {
                setSessions(data)
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

    const handleRevoke = async (session: SessionInfo) => {
        const confirmed = await confirm({
            title: session.current ? "Sign out this device?" : "Revoke session?",
            message: session.current
                ? "You are signing out the device you are using right now."
                : "That device will be signed out immediately.",
            confirmText: "Revoke",
        })

        if (!confirmed) return

        try {
            setBusy(session.id)
            setError(null)
            await accountApi.revokeSession(session.id)
            load()
            notify("Session revoked.", "success")
        } catch (caught) {
            setError(caught)
        } finally {
            setBusy(null)
        }
    }

    const showSkeleton = loading && sessions.length === 0

    return (
        <AccountBox
            title="Active sessions"
            description="Devices currently signed in to your account."
        >
            <Stack sx={{ gap: 2 }}>
                {error !== null && <ErrorAlert error={error} onRetry={reload} />}

                {showSkeleton ? (
                    <ListSkeleton rows={3} />
                ) : sessions.length === 0 ? (
                    <EmptyState
                        dense
                        icon={DevicesOther}
                        title="No active sessions"
                        description="Nothing is signed in right now. Sessions appear here as soon as you sign in on a device."
                    />
                ) : (
                    <List disablePadding>
                        {sessions.map((session) => {
                            const device = session.device ?? "Unknown device"

                            return (
                                <ListItem
                                    key={session.id}
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
                                            disabled={busy === session.id}
                                            aria-label={
                                                session.current
                                                    ? `Sign out this device, ${device}`
                                                    : `Revoke session on ${device}`
                                            }
                                            onClick={() => void handleRevoke(session)}
                                        >
                                            {session.current ? "Sign out" : "Revoke"}
                                        </AccountButton>
                                    }
                                >
                                    <ListItemIcon sx={{ mt: 0.5 }}>
                                        <Devices />
                                    </ListItemIcon>

                                    <ListItemText
                                        primary={
                                            <Box
                                                component="span"
                                                sx={{
                                                    display: "flex",
                                                    alignItems: "center",
                                                    gap: 1,
                                                    flexWrap: "wrap",
                                                }}
                                            >
                                                {device}

                                                {session.current && (
                                                    <Chip
                                                        component="span"
                                                        size="small"
                                                        variant="outlined"
                                                        color="primary"
                                                        icon={<RadioButtonChecked />}
                                                        label="This device"
                                                    />
                                                )}
                                            </Box>
                                        }
                                        secondary={`Last seen ${formatRelative(session.last_seen_at)} · started ${formatDateTime(session.created_at)} · expires ${formatRelative(session.expires_at)}`}
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
