import { Box, Chip, Divider, Stack, Typography } from "@mui/material"
import CheckCircleIcon from "@mui/icons-material/CheckCircle"
import { useEffect, useState } from "react"
import { useSearchParams } from "react-router"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import ProviderButtons from "../../../../components/ProviderButtons.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import { DiscordIcon, GoogleIcon } from "../../../../components/global/Icons.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { accountApi } from "../../../../api/account.ts"
import { formatDate } from "../../../../lib/format.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { LinkedProvider } from "../../../../api/types.ts"

const ICONS: Record<string, () => React.ReactElement> = {
    google: GoogleIcon,
    discord: DiscordIcon,
}

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
    const [searchParams, setSearchParams] = useSearchParams()

    const [linked, setLinked] = useState<LinkedProvider[]>([])
    const [error, setError] = useState<unknown>(null)

    const load = () => {
        accountApi
            .linkedProviders()
            .then(({ data }) => setLinked(data))
            .catch((caught: unknown) => setError(caught))
    }

    useEffect(load, [])

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
            title: `Unlink ${provider}?`,
            message: "You will no longer be able to sign in with this provider.",
            confirmText: "Unlink",
        })

        if (!confirmed) return

        try {
            setError(null)
            await accountApi.unlinkProvider(provider)
            load()
            notify(`Unlinked ${provider}.`, "success")
        } catch (caught) {
            // `last_credential_removal` lands here: the server refuses to leave an account with
            // no way in at all.
            setError(caught)
        }
    }

    return (
        <AccountBox
            title="Connected accounts"
            description="Link an external provider for one-click sign-in."
            requirements={[
                {
                    id: "email",
                    label: "Email verification required",
                    satisfied: user.email_verified,
                },
            ]}
            sx={{
                flex: "1 1 300px",
                minWidth: "60%",
            }}
        >
            <Stack spacing={2}>
                {error !== null && <ErrorAlert error={error} />}

                {linked.length === 0 && (
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                        No providers linked yet.
                    </Typography>
                )}

                {linked.map((identity) => {
                    const Icon = ICONS[identity.provider]

                    return (
                        <Box
                            key={identity.provider}
                            sx={{
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "space-between",
                                gap: 2,
                            }}
                        >
                            <Box
                                sx={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: 1.5,
                                    minWidth: 0,
                                }}
                            >
                                {Icon && <Icon />}

                                <Box sx={{ minWidth: 0 }}>
                                    <Typography sx={{ fontWeight: 500, textTransform: "capitalize" }}>
                                        {identity.provider}
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            color: "text.secondary",
                                            overflow: "hidden",
                                            textOverflow: "ellipsis",
                                            whiteSpace: "nowrap",
                                        }}
                                    >
                                        {identity.email ?? "linked"} · since{" "}
                                        {formatDate(identity.linked_at)}
                                    </Typography>
                                </Box>
                            </Box>

                            <Box
                                sx={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: 1,
                                    flexShrink: 0,
                                }}
                            >
                                <Chip
                                    label="Linked"
                                    color="success"
                                    size="small"
                                    icon={<CheckCircleIcon />}
                                />

                                <AccountButton
                                    variant="contained"
                                    size="small"
                                    color="error"
                                    onClick={() => void handleUnlink(identity.provider)}
                                >
                                    Unlink
                                </AccountButton>
                            </Box>
                        </Box>
                    )
                })}

                <Divider />

                <ProviderButtons
                    intent="link"
                    verb="Link"
                    exclude={linked.map((identity) => identity.provider)}
                />
            </Stack>
        </AccountBox>
    )
}
