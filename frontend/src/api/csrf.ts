/**
 * CSRF token plumbing for the double-submit cookie pattern.
 *
 * The session lives in an `HttpOnly` cookie, so the browser attaches it to *any* request to
 * this origin — including one triggered from an attacker's page. The backend therefore also
 * demands the token in an `X-CSRF-Token` header (`HttpSecurity.kt#checkCsrf`). A cross-origin
 * page can send the cookie but cannot *read* it, so it cannot produce the matching header.
 *
 * The cookie is deliberately not `HttpOnly` for exactly this reason. Its only job is to be
 * unreadable by a different origin, which the same-origin policy already guarantees.
 *
 * Two cookie names are possible: the backend adds the `__Host-` prefix whenever it issues
 * secure cookies, and drops it in plain-HTTP development.
 */

const COOKIE_NAMES = ["__Host-helium_csrf", "helium_csrf"] as const

/**
 * Last token handed to us by `GET /v1/auth/session`.
 *
 * The cookie is the source of truth (the server rotates it on every authentication), but this
 * copy covers the case where cookie parsing is blocked or the value has not landed yet.
 */
let bootstrapToken: string | null = null

export function setCsrfToken(token: string | null): void {
    bootstrapToken = token
}

function readCookie(name: string): string | null {
    const prefix = `${name}=`
    for (const part of document.cookie.split(";")) {
        const trimmed = part.trim()
        if (trimmed.startsWith(prefix)) {
            return decodeURIComponent(trimmed.slice(prefix.length))
        }
    }
    return null
}

/** The token to echo in `X-CSRF-Token`, or `null` when we have not bootstrapped yet. */
export function currentCsrfToken(): string | null {
    for (const name of COOKIE_NAMES) {
        const value = readCookie(name)
        if (value) return value
    }
    return bootstrapToken
}
