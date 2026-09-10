package dev.kamiql.helium.api

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.withCharset
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.acceptItems
import io.ktor.server.response.respondText

/**
 * The HTML face of [ProblemDetails], for the handful of endpoints a browser navigates to.
 *
 * Most of this service answers XHR, and problem+json is the right answer there — the SPA reads
 * `code` and renders its own copy. But three paths are reached by a top-level navigation, where
 * whatever the server writes *is* what the user reads:
 *
 *  * `/api/oauth2/authorize` — [dev.kamiql.helium.api.navigateToAuthorize]'s "Allow access" jump.
 *    Caddy's SPA matcher is scoped to the bare `/oauth2/authorize` path, so the `/api` prefix
 *    proxies straight here with `Accept: text/html`.
 *  * `/v1/auth/providers/{provider}/callback` — where Google and Discord return the user.
 *  * any mistyped `/v1/...` or `/oauth2/...` URL, which StatusPages answers as `not_found`.
 *
 * Those used to render a raw JSON document in the address bar. The failure was most visible at
 * the end of an OAuth sign-in — the one moment the user is least equipped to read it, because
 * they arrived from somebody else's application and cannot tell whose fault it is.
 *
 * Rendered rather than redirected. An authorization request fails precisely when its parameters
 * have not been validated, so there is no URI yet known to be safe to send the user to; bouncing
 * anywhere at that point is the open redirect the validation order exists to prevent
 * (`OAuthFlows` "validation order is load-bearing", concept §4.9). A page that renders in place
 * makes no claim about where the user should go next, which is the honest position.
 */

/**
 * Whether this caller is a browser showing the response to a person.
 *
 * Ranked by q-value rather than substring-matched: a client that says
 * `Accept: application/json, text/html;q=0.1` is asking for JSON and gets it. Anything that does
 * not mention HTML at all — every API client, and every conforming OAuth client — is unaffected,
 * so `/token`, `/revoke`, `/introspect` and `/userinfo` keep their RFC-mandated JSON bodies
 * whatever this returns.
 */
internal fun ApplicationCall.prefersHtml(): Boolean {
    val accepted = runCatching { request.acceptItems() }.getOrNull() ?: return false

    val html = accepted.firstOrNull {
        it.value == "text/html" || it.value == "application/xhtml+xml"
    } ?: return false

    val json = accepted.firstOrNull {
        it.value == "application/json" || it.value.endsWith("+json")
    }

    return json == null || html.quality >= json.quality
}

/**
 * Writes [problem] as a self-contained HTML page.
 *
 * Same status, same headers, same [ProblemDetails] — only the serialization differs, so nothing
 * a client branches on changes with the `Accept` header.
 *
 * The markup carries no script and no external reference. Production CSP is
 * `default-src 'self'; style-src 'self' 'unsafe-inline'` (infra/Caddyfile.prod), which allows the
 * inline stylesheet and would block an inline script or a webfont; the system font stack mirrors
 * the fallbacks in the SPA's own theme. `X-Content-Type-Options: nosniff` is set globally, so the
 * content type has to be exactly `text/html; charset=utf-8`.
 */
internal suspend fun ApplicationCall.respondProblemHtml(problem: ProblemDetails, status: HttpStatusCode) {
    respondText(renderErrorPage(problem), ContentType.Text.Html.withCharset(Charsets.UTF_8), status)
}

/**
 * The headline.
 *
 * [ProblemMapper.titleFor] falls back to the code with its underscores swapped for spaces, which
 * reads as "Redirect uri invalid" — fine in a JSON body a developer is reading, wrong as the
 * first line a person sees. These are phrased from the user's position: what happened to them,
 * not what the server decided.
 */
private fun headline(problem: ProblemDetails): String = when (problem.code) {
    "redirect_uri_invalid", "unauthorized_client", "invalid_scope" -> "This application cannot sign you in"
    "oauth_state_invalid", "oauth_nonce_invalid", "pkce_verifier_invalid" -> "Sign-in could not be completed"
    "invalid_token", "token_expired", "token_revoked" -> "This link is no longer valid"
    "invalid_grant" -> "This sign-in has expired"
    "provider_unavailable", "provider_denied", "provider_invalid_response" -> "Sign-in provider problem"
    "auth_required" -> "Please sign in"
    "not_found" -> "Page not found"
    "rate_limited" -> "Too many attempts"
    "temporarily_unavailable" -> "Service unavailable"
    // `title` already carries ProblemMapper's wording for everything with a considered name.
    else -> problem.title
}

/**
 * Copy for a code, kept deliberately in step with the SPA's `MESSAGES` map (`api/problem.ts`).
 *
 * Two renderers of the same error should not word it two ways. `detail` from the domain is the
 * fallback rather than the default: it is written to be safe to show (concept §5.3 forbids
 * putting anything sensitive there), but it is phrased for a developer reading a JSON body.
 */
private fun explain(problem: ProblemDetails): String = when (problem.code) {
    "auth_required" -> "Your session has expired. Sign in again to continue."
    "invalid_token", "oauth_state_invalid", "oauth_nonce_invalid" ->
        "This link is not valid. It may have been opened twice, or the sign-in may have taken too long."
    "token_expired" -> "This link has expired. Start again to get a new one."
    "token_revoked" -> "This link is no longer valid."
    "redirect_uri_invalid" ->
        "The application sent a return address that is not registered for it. " +
            "Nothing was shared and no access was granted."
    "unauthorized_client" -> "That application is not permitted to make this request."
    "invalid_scope" -> "The application asked for permissions it is not allowed to request."
    "invalid_grant" -> "This authorization is no longer valid. Start the sign-in again."
    "consent_required" -> "This application needs your approval before it can continue."
    "provider_unavailable" -> "The sign-in provider is not responding. Try again in a moment."
    "provider_denied" -> "The sign-in provider refused the request."
    "provider_invalid_response" -> "The sign-in provider returned a response we could not use."
    "account_suspended" -> "This account is suspended."
    "account_locked" -> "This account is temporarily locked."
    "account_disabled" -> "This account is disabled."
    "email_unverified" -> "Verify your email address to continue."
    "rate_limited" -> "Too many attempts. Wait a moment and try again."
    "not_found" -> "That page does not exist."
    "forbidden" -> "You do not have permission to do that."
    "temporarily_unavailable" -> "The service is temporarily unavailable. Try again shortly."
    else -> problem.detail
}

/**
 * What the user can actually do next.
 *
 * Never "try again" as a link: this page cannot resume an authorization, and offering a button
 * that silently fails a second time is worse than saying so. Where the flow began in another
 * application, the only safe way forward is to start it there again — the same stance the SPA's
 * consent screen takes when it fails.
 */
private fun nextStep(problem: ProblemDetails): String = when (problem.code) {
    "not_found" -> "Check the address, or go to your account."
    "rate_limited", "temporarily_unavailable", "provider_unavailable" ->
        "No action is needed beyond waiting. If it keeps happening, contact support."
    else ->
        "Return to the application that sent you here and start again. " +
            "That is the only way to continue safely — this page cannot resume a sign-in on its own."
}

/** Minimal, dependency-free HTML escaping for the few values interpolated below. */
private fun String.escapeHtml(): String = buildString(length) {
    for (char in this@escapeHtml) {
        when (char) {
            '&' -> append("&amp;")
            '<' -> append("&lt;")
            '>' -> append("&gt;")
            '"' -> append("&quot;")
            '\'' -> append("&#39;")
            else -> append(char)
        }
    }
}

/**
 * The page itself.
 *
 * Written as a string rather than through a templating engine or the HTML DSL: it is one page
 * with no variants, and a dependency whose whole job would be to interpolate four values is not
 * worth the packaging and version surface. Everything interpolated is escaped, and only
 * `request_id` is caller-influenced — `CallId` already constrains it to 128 alphanumerics.
 *
 * Colours are the SPA theme's, keyed off `prefers-color-scheme` so the page matches the app the
 * user was just looking at in either mode.
 */
private fun renderErrorPage(problem: ProblemDetails): String {
    val title = headline(problem).escapeHtml()
    val message = explain(problem).escapeHtml()
    val guidance = nextStep(problem).escapeHtml()
    val code = problem.code.escapeHtml()
    val requestId = problem.requestId?.escapeHtml()

    val reference = if (requestId != null) {
        """
        <p class="reference">
          <span>Reference</span>
          <code>$requestId</code>
        </p>
        """.trimIndent()
    } else {
        ""
    }

    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>$title — HeliumID</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f6f7f9;
    --surface: #ffffff;
    --text: #14161a;
    --muted: #5b6270;
    --border: #e3e6ea;
    --accent: #0098db;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0e1013;
      --surface: #16191e;
      --text: #eceef1;
      --muted: #9aa2ae;
      --border: #262b32;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }
  main {
    width: 100%;
    max-width: 27rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    box-shadow: 0 1px 2px rgba(0, 0, 0, .04), 0 8px 24px rgba(0, 0, 0, .06);
  }
  .brand {
    font-size: .8125rem;
    font-weight: 600;
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--accent);
    margin: 0 0 1.5rem;
  }
  h1 { font-size: 1.375rem; font-weight: 600; margin: 0 0 .625rem; }
  p { margin: 0 0 1rem; }
  .muted { color: var(--muted); font-size: .9375rem; }
  .reference {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: .5rem;
    margin: 1.5rem 0 0;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    font-size: .8125rem;
    color: var(--muted);
  }
  code {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: .8125rem;
    overflow-wrap: anywhere;
  }
  a { color: var(--accent); }
  @media (max-width: 30rem) { main { padding: 1.5rem; } }
</style>
</head>
<body>
<main role="main">
  <p class="brand">HeliumID</p>
  <h1>$title</h1>
  <p>$message</p>
  <p class="muted">$guidance</p>
  $reference
  <p class="reference"><span>Error code</span> <code>$code</code></p>
</main>
</body>
</html>
""".trimIndent()
}
