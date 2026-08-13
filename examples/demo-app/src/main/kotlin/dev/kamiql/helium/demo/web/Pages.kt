package dev.kamiql.helium.demo.web

import dev.kamiql.helium.client.AdminUserResponse
import dev.kamiql.helium.client.UserResponse
import dev.kamiql.helium.demo.auth.DemoSession
import dev.kamiql.helium.demo.domain.DocumentRole
import dev.kamiql.helium.demo.domain.DocumentView
import kotlinx.html.*

/**
 * Server-rendered views.
 *
 * Plain HTML with a little inline CSS, on purpose: a build step and a component framework would
 * be the largest thing in this example and would teach nothing about HeliumID.
 */

private const val STYLE = """
  :root { color-scheme: light dark; --line: #8883; --muted: #6b7280; --accent: #5865F2; }
  * { box-sizing: border-box; }
  body { font: 15px/1.55 system-ui, sans-serif; margin: 0; }
  main { max-width: 62rem; margin: 0 auto; padding: 1.5rem 1.25rem 4rem; }
  header { border-bottom: 1px solid var(--line); }
  header > div { max-width: 62rem; margin: 0 auto; padding: .9rem 1.25rem;
                 display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
  header nav { display: flex; gap: 1rem; margin-left: auto; align-items: center; }
  a { color: var(--accent); }
  h1 { font-size: 1.45rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.1rem; margin: 2rem 0 .6rem; }
  p.lede { color: var(--muted); margin: 0 0 1.5rem; }
  .card { border: 1px solid var(--line); border-radius: .6rem; padding: 1rem; margin: .6rem 0; }
  .row { display: flex; gap: .75rem; align-items: baseline; flex-wrap: wrap; }
  .muted { color: var(--muted); font-size: .87rem; }
  .tag { border: 1px solid var(--line); border-radius: 1rem; padding: .05rem .55rem;
         font-size: .78rem; color: var(--muted); }
  code, .mono { font-family: ui-monospace, monospace; font-size: .85em; }
  button, .button { font: inherit; padding: .45rem .9rem; border-radius: .4rem;
                    border: 1px solid var(--line); background: transparent; cursor: pointer; }
  button.primary { background: var(--accent); color: #fff; border-color: transparent; }
  button.danger { color: #b91c1c; }
  input, textarea, select { font: inherit; padding: .45rem .55rem; border-radius: .4rem;
                            border: 1px solid var(--line); background: transparent; width: 100%; }
  form.stack { display: grid; gap: .6rem; max-width: 34rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: .45rem .5rem; border-bottom: 1px solid var(--line);
           vertical-align: top; }
  .note { border-left: 3px solid var(--accent); padding: .6rem .9rem; margin: 1rem 0;
          background: #5865F20f; border-radius: 0 .4rem .4rem 0; }
  .warn { border-left-color: #d97706; background: #d977060f; }
  .grid { display: grid; gap: .6rem; grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr)); }
  .overflow { overflow-x: auto; }
"""

/** Page shell. [session] being null is what switches the header between signed in and out. */
fun HTML.page(title: String, session: DemoSession?, block: MAIN.() -> Unit) {
    head {
        meta(charset = "utf-8")
        meta(name = "viewport", content = "width=device-width, initial-scale=1")
        title { +"$title — Helium Demo" }
        style { unsafe { +STYLE } }
    }
    body {
        header {
            div {
                strong { a(href = "/") { +"Helium Demo Workspace" } }
                nav {
                    if (session != null) {
                        a(href = "/") { +"Documents" }
                        if (session.user.permissions.contains("admin:user:read")) {
                            a(href = "/admin") { +"Admin" }
                        }
                        a(href = "/debug/session") { +"Session" }
                        span(classes = "muted") { +session.user.username }
                        form(action = "/logout", method = FormMethod.post) {
                            style = "display:inline"
                            button { +"Sign out" }
                        }
                    } else {
                        a(href = "/login", classes = "button") { +"Sign in with HeliumID" }
                    }
                }
            }
        }
        main { block() }
    }
}

/** Landing page for a visitor with no session. */
fun MAIN.signedOut(error: String?) {
    h1 { +"Sign in to continue" }
    p(classes = "lede") {
        +"This example application uses HeliumID as its identity provider, over OAuth 2.0 "
        +"Authorization Code with PKCE."
    }

    if (error != null) {
        div(classes = "note warn") {
            strong { +"Sign-in did not complete: " }
            code { +error }
            p(classes = "muted") { +explainLoginError(error) }
        }
    }

    a(href = "/login", classes = "button") { +"Sign in with HeliumID" }

    h2 { +"What this demonstrates" }
    div(classes = "grid") {
        axisCard(
            "Your documents",
            "Roles this application keeps itself — owner, editor, viewer, per document. " +
                "HeliumID knows nothing about them, and should not: it has no per-application " +
                "permissions and no tenancy.",
        )
        axisCard(
            "HeliumID permissions",
            "Read from /v1/me after sign-in and used to gate the admin area. They appear in no " +
                "token at all — not the access token, not the ID token, not /userinfo.",
        )
        axisCard(
            "OAuth scopes",
            "workspace:read and workspace:write, checked on this app's own bearer API with " +
                "requireScope. They bound what this application may do, not what you may do.",
        )
    }
}

private fun FlowContent.axisCard(title: String, body: String) {
    div(classes = "card") {
        strong { +title }
        p(classes = "muted") { +body }
    }
}

private fun explainLoginError(code: String): String = when (code) {
    "state_mismatch" -> "The callback could not be tied to the sign-in this browser started. " +
        "That is the CSRF defence doing its job; start again."
    "no_pending_login" -> "There was no sign-in in progress, or it had already been used or expired. " +
        "Each authorization response is accepted exactly once."
    "id_token_invalid" -> "The ID token failed verification — signature, issuer, audience or nonce."
    "token_exchange_failed" -> "The authorization code could not be exchanged. It is single-use and " +
        "lives 60 seconds."
    "authorization_refused" -> "Access was declined at the consent screen."
    "missing_id_token" -> "No ID token came back, although the openid scope was requested."
    else -> "Start again from the sign-in button."
}

// --- workspace ------------------------------------------------------------------------

fun MAIN.workspace(session: DemoSession, documents: List<DocumentView>, notice: String?) {
    h1 { +"Documents" }
    p(classes = "lede") {
        +"Signed in as ${session.user.email}. Documents you own or that were shared with you."
    }

    if (notice != null) div(classes = "note") { +notice }

    if (documents.isEmpty()) {
        div(classes = "card") {
            p { +"Nothing here yet. Create a document below." }
        }
    } else {
        documents.forEach { view ->
            div(classes = "card") {
                div(classes = "row") {
                    strong { a(href = "/documents/${view.document.id}") { +view.document.title } }
                    span(classes = "tag") { +view.role.label }
                }
                p(classes = "muted") {
                    +"Updated ${view.document.updatedAt} · ${view.document.grants.size} member(s)"
                }
            }
        }
    }

    h2 { +"New document" }
    form(action = "/documents", method = FormMethod.post, classes = "stack") {
        label {
            +"Title"
            textInput(name = "title") { required = true; placeholder = "Quarterly plan" }
        }
        label {
            +"Body"
            textArea { name = "body"; rows = "4" }
        }
        div { button(classes = "primary") { +"Create" } }
    }
}

fun MAIN.documentDetail(session: DemoSession, view: DocumentView, notice: String?, error: String?) {
    val document = view.document

    div(classes = "row") {
        h1 { +document.title }
        span(classes = "tag") { +"You are ${view.role.label.lowercase()}" }
    }
    p(classes = "lede") { +"Created ${document.createdAt}" }

    if (notice != null) div(classes = "note") { +notice }
    if (error != null) div(classes = "note warn") { +error }

    div(classes = "card") { p { +document.body.ifBlank { "(empty)" } } }

    h2 { +"Members" }
    div(classes = "overflow") {
        table {
            tr { th { +"Subject" }; th { +"Role" } }
            document.grants.forEach { (subject, role) ->
                tr {
                    td {
                        span(classes = "mono") { +subject }
                        if (subject == session.subject) span(classes = "muted") { +" (you)" }
                    }
                    td { +role.label }
                }
            }
        }
    }

    if (view.role.canWrite) {
        h2 { +"Edit" }
        form(action = "/documents/${document.id}", method = FormMethod.post, classes = "stack") {
            label {
                +"Title"
                textInput(name = "title") { value = document.title; required = true }
            }
            label {
                +"Body"
                textArea { name = "body"; rows = "4"; +document.body }
            }
            div { button(classes = "primary") { +"Save" } }
        }
    } else {
        div(classes = "note warn") {
            +"You have the viewer role on this document, so the edit form is not shown. "
            +"Posting to it anyway is refused server-side — the UI is not the check."
        }
    }

    if (view.role.canShare) {
        h2 { +"Share" }
        p(classes = "muted") {
            +"By HeliumID user id (the "
            code { +"sub" }
            +" claim). Look one up under Admin, or read it from another account's Session page. "
            +"Sharing by email address is deliberately not offered: matching accounts by email is "
            +"how account-linking takeovers start."
        }
        form(action = "/documents/${document.id}/share", method = FormMethod.post, classes = "stack") {
            label {
                +"User id"
                textInput(name = "subject") { required = true; placeholder = "0193f2c1-…" }
            }
            label {
                +"Role"
                select {
                    name = "role"
                    listOf(DocumentRole.VIEWER, DocumentRole.EDITOR).forEach {
                        option { value = it.name; +it.label }
                    }
                }
            }
            div { button(classes = "primary") { +"Share" } }
        }
    }

    if (view.role.canDelete) {
        h2 { +"Delete" }
        form(action = "/documents/${document.id}/delete", method = FormMethod.post) {
            button(classes = "danger") { +"Delete this document" }
        }
    }
}

// --- admin ----------------------------------------------------------------------------

fun MAIN.adminPage(session: DemoSession, users: List<AdminUserResponse>, notice: String?, error: String?) {
    h1 { +"Administration" }
    p(classes = "lede") {
        +"Backed by HeliumID's own "
        code { +"/v1/admin" }
        +" API, using your access token."
    }

    if (notice != null) div(classes = "note") { +notice }
    if (error != null) div(classes = "note warn") { +error }

    div(classes = "note") {
        strong { +"Why most buttons here are read-only." }
        p {
            +"Nearly every write under "
            code { +"/v1/admin" }
            +" declares "
            code { +"ReauthenticatedWithin(5 minutes)" }
            +", and that requirement rejects any principal that is not a browser session at "
            +"HeliumID itself. A bearer token can never satisfy it, however privileged its owner. "
            +"Two writes are exceptions because they declare no reauthentication: revoking a "
            +"user's sessions, and scope CRUD."
        }
        p(classes = "muted") {
            +"The suspend button below is wired to "
            code { +"PUT /v1/admin/users/{id}/status" }
            +" on purpose, so you can watch it fail with "
            code { +"reauthentication_required" }
            +" rather than wonder why it is missing."
        }
    }

    h2 { +"Users" }
    div(classes = "overflow") {
        table {
            tr {
                th { +"User" }; th { +"Status" }; th { +"Roles" }; th { +"Actions" }
            }
            users.forEach { user ->
                tr {
                    td {
                        +user.username
                        div(classes = "muted mono") { +user.id }
                    }
                    td { +user.status }
                    td { +user.roles.joinToString(", ").ifBlank { "—" } }
                    td {
                        div(classes = "row") {
                            form(action = "/admin/users/${user.id}/revoke-sessions", method = FormMethod.post) {
                                button { +"Revoke sessions" }
                            }
                            form(action = "/admin/users/${user.id}/suspend", method = FormMethod.post) {
                                button(classes = "danger") { +"Suspend" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** Shown when the signed-in user lacks the HeliumID permission a section requires. */
fun MAIN.forbidden(session: DemoSession, permission: String) {
    h1 { +"Not permitted" }
    p(classes = "lede") {
        +"This section needs the "
        code { +permission }
        +" permission, which your account does not hold."
    }
    div(classes = "card") {
        p { strong { +"Your permissions" } }
        p(classes = "mono") { +session.user.permissions.joinToString(", ").ifBlank { "—" } }
        p(classes = "muted") {
            +"Granted through roles in HeliumID. An administrator can change them under "
            +"Admin → Roles in the HeliumID console; the change takes effect on your next request, "
            +"with no sign-out needed."
        }
    }
    a(href = "/") { +"Back to your documents" }
}

// --- session debug ----------------------------------------------------------------------

fun MAIN.sessionPage(session: DemoSession, user: UserResponse, accessToken: String?) {
    h1 { +"Session" }
    p(classes = "lede") {
        +"What this application holds about you. Shown because it is a demo — a real application "
        +"would never render an access token into a page."
    }

    h2 { +"Identity" }
    div(classes = "overflow") {
        table {
            tr { th { +"sub" }; td { span(classes = "mono") { +session.subject } } }
            tr { th { +"Username" }; td { +user.username } }
            tr { th { +"Email" }; td { +"${user.email} (verified: ${user.emailVerified})" } }
            tr { th { +"MFA" }; td { +if (user.mfaEnabled) "enabled" else "not enabled" } }
            tr { th { +"Signed in at" }; td { +session.authenticatedAt.toString() } }
        }
    }

    h2 { +"Roles and permissions" }
    p(classes = "muted") {
        +"From "
        code { +"GET /v1/me" }
        +", read fresh from the database on every call. They are in no token, so revoking a role "
        +"takes effect immediately without any refresh."
    }
    div(classes = "card") {
        p { strong { +"Roles: " }; +user.roles.joinToString(", ").ifBlank { "—" } }
        p {
            strong { +"Permissions: " }
            span(classes = "mono") { +user.permissions.joinToString(", ").ifBlank { "—" } }
        }
    }

    h2 { +"Granted scopes" }
    p(classes = "muted") {
        +"What this application was allowed to do on your behalf — a different question from what "
        +"you are allowed to do."
    }
    div(classes = "card") { span(classes = "mono") { +session.grantedScopes.joinToString(" ") } }

    h2 { +"Access token" }
    p(classes = "muted") {
        +"Expires ${session.accessTokenExpiresAt}. Refreshed automatically, and the refresh token "
        +"rotates on every use. Try the scope-protected API with it:"
    }
    div(classes = "card overflow") {
        pre { code { +"curl -H \"Authorization: Bearer ${accessToken ?: "…"}\" \\\n  http://localhost:8081/api/documents" } }
    }
}
