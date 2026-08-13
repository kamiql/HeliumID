import {
    Box,
    Chip,
    Divider,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Stack,
    Typography,
} from "@mui/material"
import { CheckCircleOutlined, LinkOff, Login } from "@mui/icons-material"
import { useEffect, useState } from "react"
import { useSearchParams } from "react-router"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { ACCOUNT_ANCHORS } from "../../../../components/dashboard/account/AccountRequirement.tsx"
import { EmptyState, ListSkeleton } from "../../../../components/ui/StateView.tsx"
import ProviderButtons from "../../../../components/ProviderButtons.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { PROVIDER_ICONS, providerLabel } from "../../../../lib/providers.ts"
import { useUser } from "../../../../hooks/useUser.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { useProviders } from "../../../../hooks/useProviders.ts"
import { accountApi } from "../../../../api/account.ts"
import { formatDate } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { LinkedProvider } from "../../../../api/types.ts"

/**
 * External identities linked to this account.
 *
 * Linking always starts from an authenticated session (`intent=link`). Accounts are never
 * merged automatically by matching email addresses — that is how provider-linking takeovers
 * happen — so an unknown identity must be attached deliberately from here.
 */
export default function LinkedProvidersBox() {
    const user = useUser()
    const { confirm } = useConfirm()
    const providers = useProviders()
    const [searchParams, setSearchParams] = useSearchParams()

    const [linked, setLinked] = useState<LinkedProvider[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<unknown>(null)

    // No `setLoading(true)` here: `loading` starts true for the first fetch, and a refresh
    // after linking or unlinking should update the list in place rather than replace it with
    // a skeleton. The global progress bar in the app shell signals the in-flight request.
    const load = () => {
        accountApi
            .linkedProviders()
            .then(({ data }) => {
                setLinked(data)
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

    // The provider callback bounces back to /account?linked=<provider>.
    useEffect(() => {
        const justLinked = searchParams.get("linked")
        if (!justLinked) return
        notify(`Linked ${justLinked}.`, "success")
        searchParams.delete("linked")
        setSearchParams(searchParams, { replace: true })
    }, [searchParams, setSearchParams])

    const handleUnlink = async (provider: string) => {
        const confirmed = await confirm({
            title: `Unlink ${providerLabel(provider)}?`,
            message: "You will no longer be able to sign in with this provider.",
            confirmText: "Unlink",
        })

        if (!confirmed) return

        try {
            setError(null)
            await accountApi.unlinkProvider(provider)
            load()
            notify(`Unlinked ${providerLabel(provider)}.`, "success")
        } catch (caught) {
            // `last_credential_removal` lands here: the server refuses to leave an account with
            // no way in at all.
            setError(caught)
        }
    }

    const showSkeleton = loading && linked.length === 0
    const linkable = providers.filter(
        (provider) => !linked.some((identity) => identity.provider === provider),
    )

    return (
        <AccountBox
            title="Connected accounts"
            description="Link an external provider for one-click sign-in."
            requirements={[
                {
                    id: "email",
                    label: "Verify your email address first",
                    hint: "An unverified address cannot be used to prove an external identity is yours.",
                    fix: { label: "Go to email address", anchor: ACCOUNT_ANCHORS.email },
                    satisfied: user.email_verified,
                },
            ]}
        >
            <Stack sx={{ gap: 2 }}>
                {error !== null && <ErrorAlert error={error} onRetry={reload} />}

                {showSkeleton ? (
                    <ListSkeleton rows={2} />
                ) : linked.length === 0 ? (
                    <EmptyState
                        dense
                        icon={LinkOff}
                        title="No connected accounts"
                        description="Link a provider to sign in with one click. Your HeliumID password keeps working either way."
                    />
                ) : (
                    <List disablePadding>
                        {linked.map((identity) => {
                            const Icon = PROVIDER_ICONS[identity.provider]
                            const name = providerLabel(identity.provider)

                            return (
                                <ListItem
                                    key={identity.provider}
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
                                            aria-label={`Unlink ${name}`}
                                            onClick={() => void handleUnlink(identity.provider)}
                                        >
                                            Unlink
                                        </AccountButton>
                                    }
                                >
                                    <ListItemIcon sx={{ mt: 0.5 }}>
                                        {Icon ? <Icon /> : <Login />}
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
                                                {name}

                                                <Chip
                                                    component="span"
                                                    size="small"
                                                    variant="outlined"
                                                    color="success"
                                                    icon={<CheckCircleOutlined />}
                                                    label="Linked"
                                                />
                                            </Box>
                                        }
                                        secondary={`${identity.email ?? "linked"} · since ${formatDate(identity.linked_at)}`}
                                        sx={{ my: 0, wordBreak: "break-word" }}
                                    />
                                </ListItem>
                            )
                        })}
                    </List>
                )}

                {/*
                 * The provider buttons leave the app entirely, so they are withheld rather than
                 * disabled while the box is blocked — a greyed-out button that still starts an
                 * OAuth redirect would be worse than no button at all.
                 */}
                {user.email_verified && linkable.length > 0 && (
                    <>
                        <Divider />

                        <Box>
                            <Typography variant="subtitle2" sx={{ mb: 1 }}>
                                Add a provider
                            </Typography>

                            <ProviderButtons
                                intent="link"
                                verb="Link"
                                exclude={linked.map((identity) => identity.provider)}
                            />
                        </Box>
                    </>
                )}
            </Stack>
        </AccountBox>
    )
}
