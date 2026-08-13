import { Button, Stack } from "@mui/material"
import { Login } from "@mui/icons-material"
import { PROVIDER_ICONS, providerLabel } from "../lib/providers.ts"
import { startProviderFlow } from "../api/auth.ts"
import { useProviders } from "../hooks/useProviders.ts"

type ProviderButtonsProps = {
    /** `"link"` attaches the provider to the current account instead of signing in. */
    intent?: "link"
    /** Providers already linked, so the account page can hide them. */
    exclude?: string[]
    verb?: string
}

/**
 * The provider list is fetched from `GET /v1/auth/providers` rather than hard-coded.
 *
 * The server decides which providers exist; offering one it does not know would send the user
 * into a dead redirect, and hard-coding the set means every deployment change needs a rebuild.
 */
export default function ProviderButtons({
    intent,
    exclude = [],
    verb = "Sign in with",
}: ProviderButtonsProps) {
    const providers = useProviders()

    const available = providers.filter((provider) => !exclude.includes(provider))
    if (available.length === 0) return null

    return (
        <Stack spacing={1.5}>
            {available.map((provider) => {
                // Marks and names come from the shared registry, so a provider the server
                // enables is spelled the way its owner spells it — `github` is GitHub.
                const Icon = PROVIDER_ICONS[provider]

                return (
                    <Button
                        key={provider}
                        fullWidth
                        variant="outlined"
                        color="inherit"
                        startIcon={Icon ? <Icon /> : <Login />}
                        onClick={() => startProviderFlow(provider, intent)}
                    >
                        {verb} {providerLabel(provider)}
                    </Button>
                )
            })}
        </Stack>
    )
}
