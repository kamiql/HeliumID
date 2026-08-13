import type { ComponentType } from "react"
import type { SvgIconProps } from "@mui/material/SvgIcon"
import { DiscordIcon, GitHubIcon, GoogleIcon } from "../components/global/Icons.tsx"

/**
 * Presentation details for the external identity providers.
 *
 * Kept out of `Icons.tsx` so that file exports components only — a module that mixes
 * components with plain values breaks Vite's fast refresh for everything importing it.
 *
 * The provider list itself always comes from `GET /v1/auth/providers`. This map only decides
 * how a known provider looks; one the server enables without an entry here still renders,
 * with a generic icon and a capitalised name, rather than disappearing from the UI.
 */
export const PROVIDER_ICONS: Record<string, ComponentType<SvgIconProps>> = {
    google: GoogleIcon,
    discord: DiscordIcon,
    github: GitHubIcon,
}

const PROVIDER_LABELS: Record<string, string> = {
    google: "Google",
    discord: "Discord",
    github: "GitHub",
}

/** Human-readable provider name, e.g. `github` → `GitHub` rather than `Github`. */
export function providerLabel(provider: string): string {
    return PROVIDER_LABELS[provider] ?? provider.charAt(0).toUpperCase() + provider.slice(1)
}
