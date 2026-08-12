import { Box, Chip, Stack, Typography } from "@mui/material"
import DevicesIcon from "@mui/icons-material/Devices"
import { useEffect, useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
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
    const [error, setError] = useState<unknown>(null)
    const [busy, setBusy] = useState<string | null>(null)

    const load = () => {
        accountApi
            .sessions()
            .then(({ data }) => setSessions(data))
            .catch((caught: unknown) => setError(caught))
    }

    useEffect(load, [])

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

    return (
        <AccountBox
            title="Active sessions"
            description="Devices currently signed in to your account."
            sx={{ flex: "1 1 100%" }}
        >
            <Stack spacing={2}>
                {error !== null && <ErrorAlert error={error} />}

                {sessions.length === 0 && (
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                        No active sessions found.
                    </Typography>
                )}

                {sessions.map((session) => (
                    <Box
                        key={session.id}
                        sx={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: 2,
                            flexWrap: "wrap",
                        }}
                    >
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, minWidth: 0 }}>
                            <DevicesIcon sx={{ color: "text.secondary" }} />

                            <Box sx={{ minWidth: 0 }}>
                                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                                    <Typography sx={{ fontWeight: 500 }} noWrap>
                                        {session.device ?? "Unknown device"}
                                    </Typography>

                                    {session.current && (
                                        <Chip label="This device" color="primary" size="small" />
                                    )}
                                </Stack>

                                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                    Last seen {formatRelative(session.last_seen_at)} · started{" "}
                                    {formatDateTime(session.created_at)} · expires{" "}
                                    {formatRelative(session.expires_at)}
                                </Typography>
                            </Box>
                        </Box>

                        <AccountButton
                            variant="outlined"
                            size="small"
                            color="error"
                            disabled={busy === session.id}
                            onClick={() => void handleRevoke(session)}
                        >
                            {session.current ? "Sign out" : "Revoke"}
                        </AccountButton>
                    </Box>
                ))}
            </Stack>
        </AccountBox>
    )
}
