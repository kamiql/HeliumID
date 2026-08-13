import { Box, Chip, List, ListItem, ListItemIcon, ListItemText, Stack } from "@mui/material"
import { Apps, AppShortcut, VerifiedUser } from "@mui/icons-material"
import { useEffect, useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { EmptyState, ListSkeleton } from "../../../../components/ui/StateView.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { accountApi } from "../../../../api/account.ts"
import { formatDate, formatRelative } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { AuthorizedApp } from "../../../../api/types.ts"

/**
 * Applications that can reach this account.
 *
 * The counterpart to the connected-accounts box: those are the providers you sign in *with*,
 * these are the OAuth clients holding access *to* your account. Apps with no consent record of
 * their own are listed too — a first-party client registered to skip the consent screen still
 * has access, and hiding it would make this list a comfortable lie.
 */
export default function AuthorizedAppsBox() {
    const { confirm } = useConfirm()

    const [apps, setApps] = useState<AuthorizedApp[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<unknown>(null)
    const [busy, setBusy] = useState<string | null>(null)

    // No `setLoading(true)` here: `loading` starts true for the first fetch, and a refresh after
    // a revoke should update the list in place rather than replace it with a skeleton. The
    // global progress bar in the app shell already signals the in-flight request.
    const load = () => {
        accountApi
            .authorizations()
            .then(({ data }) => {
                setApps(data)
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

    const handleRevoke = async (app: AuthorizedApp) => {
        const confirmed = await confirm({
            title: `Revoke access for ${app.name}?`,
            message:
                "The app loses its tokens immediately and has to ask for your approval again the next time you sign in to it.",
            confirmText: "Revoke",
        })

        if (!confirmed) return

        try {
            setBusy(app.client_id)
            setError(null)
            await accountApi.revokeAuthorization(app.client_id)
            load()
            notify(`Revoked access for ${app.name}.`, "success")
        } catch (caught) {
            setError(caught)
        } finally {
            setBusy(null)
        }
    }

    const showSkeleton = loading && apps.length === 0

    return (
        <AccountBox
            title="Authorized applications"
            description="Apps and services you have given access to your account."
        >
            <Stack sx={{ gap: 2 }}>
                {error !== null && <ErrorAlert error={error} onRetry={reload} />}

                {showSkeleton ? (
                    <ListSkeleton rows={2} />
                ) : apps.length === 0 ? (
                    <EmptyState
                        dense
                        icon={AppShortcut}
                        title="No authorized applications"
                        description="Apps appear here once you sign in to them with your HeliumID account."
                    />
                ) : (
                    <List disablePadding>
                        {apps.map((app) => {
                            const activity =
                                app.last_authorized_at === null
                                    ? "No active tokens"
                                    : `Last authorized ${formatRelative(app.last_authorized_at)}`

                            return (
                                <ListItem
                                    key={app.client_id}
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
                                            disabled={busy === app.client_id}
                                            aria-label={`Revoke access for ${app.name}`}
                                            onClick={() => void handleRevoke(app)}
                                        >
                                            Revoke
                                        </AccountButton>
                                    }
                                >
                                    <ListItemIcon sx={{ mt: 0.5 }}>
                                        <Apps />
                                    </ListItemIcon>

                                    {/*
                                     * `disableTypography` because the secondary slot holds chips:
                                     * MUI would otherwise wrap it in a <p>, and a Chip renders a
                                     * div, which is invalid nesting.
                                     */}
                                    <ListItemText
                                        disableTypography
                                        sx={{ my: 0, wordBreak: "break-word" }}
                                        primary={
                                            <Box
                                                sx={{
                                                    display: "flex",
                                                    alignItems: "center",
                                                    gap: 1,
                                                    flexWrap: "wrap",
                                                    fontSize: 16,
                                                }}
                                            >
                                                {app.name}

                                                {!app.consented && (
                                                    <Chip
                                                        size="small"
                                                        variant="outlined"
                                                        color="primary"
                                                        icon={<VerifiedUser />}
                                                        label="First-party"
                                                    />
                                                )}
                                            </Box>
                                        }
                                        secondary={
                                            <Stack sx={{ gap: 1, mt: 0.5 }}>
                                                <Box sx={{ color: "text.secondary", fontSize: 14 }}>
                                                    {activity} · authorized {formatDate(app.authorized_at)}
                                                </Box>

                                                {app.scopes.length > 0 && (
                                                    <Box
                                                        sx={{
                                                            display: "flex",
                                                            gap: 0.5,
                                                            flexWrap: "wrap",
                                                        }}
                                                    >
                                                        {app.scopes.map((scope) => (
                                                            <Chip
                                                                key={scope.name}
                                                                size="small"
                                                                variant="outlined"
                                                                // The catalogue sentence is what
                                                                // the consent screen showed, so it
                                                                // is what the user actually agreed
                                                                // to — the bare scope name only
                                                                // means something to developers.
                                                                label={scope.description}
                                                            />
                                                        ))}
                                                    </Box>
                                                )}
                                            </Stack>
                                        }
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
