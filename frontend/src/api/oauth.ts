import { api } from "./axios.ts"
import type { ConsentPrompt } from "./types.ts"

/**
 * The authorization endpoint, as the built-in consent UI uses it.
 *
 * Caddy serves the SPA for `/oauth2/authorize`, so the consent screen is a front-end route that
 * re-issues the very same query string against the API. Three outcomes are possible:
 *
 *  * consent needed  — `200` with a [ConsentPrompt] for us to render;
 *  * consent not needed — a `302` to the client's redirect URI, which XHR cannot usefully
 *    follow (it is cross-origin), so the caller falls back to a full-page navigation;
 *  * an error — problem+json, surfaced as a [HeliumError].
 */
export const oauthApi = {
    prompt: (query: URLSearchParams) =>
        api.get<ConsentPrompt>("/oauth2/authorize", {
            params: query,
            headers: { Accept: "application/json" },
        }),
}

/**
 * Hands the browser to the real authorization endpoint.
 *
 * A full navigation is mandatory: only the browser can follow the `302` to the relying party's
 * `redirect_uri`, and the authorization code must never pass through this app.
 */
export function navigateToAuthorize(query: URLSearchParams, consentGranted: boolean): void {
    const params = new URLSearchParams(query)
    if (consentGranted) {
        params.set("consent", "granted")
    }
    window.location.assign(`/api/oauth2/authorize?${params.toString()}`)
}
