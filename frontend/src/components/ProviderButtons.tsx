import { Button, Stack } from "@mui/material"
import { Login } from "@mui/icons-material"
import type { ReactElement } from "react"
import { DiscordIcon, GoogleIcon } from "./global/Icons.tsx"
import { startProviderFlow } from "../api/auth.ts"
import { useProviders } from "../hooks/useProviders.ts"

const ICONS: Record<string, () => ReactElement> = {
    google: GoogleIcon,
    discord: DiscordIcon,
}

function label(provider: string): string {
    return provider.charAt(0).toUpperCase() + provider.slice(1)
}

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
        <Stack spacing={2}>
            {available.map((provider) => {
                const Icon = ICONS[provider]

                return (
                    <Button
                        key={provider}
                        fullWidth
                        variant="outlined"
                        startIcon={Icon ? <Icon /> : <Login />}
                        onClick={() => startProviderFlow(provider, intent)}
                    >
                        {verb} {label(provider)}
                    </Button>
                )
            })}
        </Stack>
    )
}
