package dev.kamiql.helium.demo.web

import dev.kamiql.helium.client.HeliumApiException
import dev.kamiql.helium.client.HeliumError
import dev.kamiql.helium.client.HeliumIdClient
import dev.kamiql.helium.demo.DemoConfig
import dev.kamiql.helium.demo.auth.DemoSession
import dev.kamiql.helium.demo.auth.SessionCookie
import dev.kamiql.helium.demo.auth.SessionStore
import dev.kamiql.helium.demo.domain.DocumentRole
import dev.kamiql.helium.demo.domain.Workspace
import dev.kamiql.helium.demo.domain.WorkspaceError
import dev.kamiql.helium.demo.domain.WorkspaceResult
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.html.respondHtml
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.sessions.clear
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import java.time.Clock

/**
 * Everything a browser talks to.
 *
 * The pattern in every handler: resolve the session, get a usable access token, act. The token
 * never reaches the browser and is never stored anywhere but the server-side session.
 */
fun Route.webRoutes(
    config: DemoConfig,
    client: HeliumIdClient,
    sessions: SessionStore,
    workspace: Workspace,
    clock: Clock,
) {

    get("/") {
        val session = call.currentSession(sessions)
        if (session == null) {
            call.respondHtml { page("Sign in", null) { signedOut(call.request.queryParameters["error"]) } }
            return@get
        }

        val documents = workspace.visibleTo(session.subject)
        call.respondHtml {
            page("Documents", session) {
                workspace(session, documents, call.request.queryParameters["notice"])
            }
        }
    }

    // --- documents ----------------------------------------------------------------

    post("/documents") {
        val session = call.requireSession(sessions) ?: return@post
        val form = call.receiveParameters()
        val title = form["title"]?.trim().orEmpty()
        if (title.isBlank()) {
            call.respondRedirect("/?notice=A+title+is+required.")
            return@post
        }

        val document = workspace.create(session.subject, title, form["body"].orEmpty(), clock.instant())
        call.respondRedirect("/documents/${document.id}")
    }

    get("/documents/{id}") {
        val session = call.requireSession(sessions) ?: return@get
        val id = call.parameters["id"]?.toLongOrNull() ?: return@get call.respondRedirect("/")

        when (val result = workspace.read(session.subject, id)) {
            is WorkspaceResult.Ok -> call.respondHtml {
                page(result.value.document.title, session) {
                    documentDetail(
                        session,
                        result.value,
                        call.request.queryParameters["notice"],
                        call.request.queryParameters["error"],
                    )
                }
            }
            // A document the caller has no grant on answers exactly like one that does not exist.
            is WorkspaceResult.Failed -> call.respondRedirect("/?notice=No+such+document.")
        }
    }

    post("/documents/{id}") {
        val session = call.requireSession(sessions) ?: return@post
        val id = call.parameters["id"]?.toLongOrNull() ?: return@post call.respondRedirect("/")
        val form = call.receiveParameters()

        val result = workspace.update(
            subject = session.subject,
            id = id,
            title = form["title"]?.trim().orEmpty(),
            body = form["body"].orEmpty(),
            now = clock.instant(),
        )
        call.redirectAfter(result, id, "Saved.")
    }

    post("/documents/{id}/share") {
        val session = call.requireSession(sessions) ?: return@post
        val id = call.parameters["id"]?.toLongOrNull() ?: return@post call.respondRedirect("/")
        val form = call.receiveParameters()

        val role = runCatching { DocumentRole.valueOf(form["role"].orEmpty()) }.getOrNull()
            ?: DocumentRole.VIEWER
        val subject = form["subject"]?.trim().orEmpty()
        if (subject.isBlank()) {
            call.respondRedirect("/documents/$id?error=A+user+id+is+required.")
            return@post
        }

        val result = workspace.share(session.subject, id, subject, role, clock.instant())
        call.redirectAfter(result, id, "Shared.")
    }

    post("/documents/{id}/delete") {
        val session = call.requireSession(sessions) ?: return@post
        val id = call.parameters["id"]?.toLongOrNull() ?: return@post call.respondRedirect("/")

        when (val result = workspace.delete(session.subject, id)) {
            is WorkspaceResult.Ok -> call.respondRedirect("/?notice=Document+deleted.")
            is WorkspaceResult.Failed -> call.respondRedirect(
                "/documents/$id?error=${result.error.describe().urlEncoded()}",
            )
        }
    }

    // --- admin --------------------------------------------------------------------

    /*
     * Gated on a HeliumID permission, not on a scope and not on a role claim.
     *
     * `admin:user:read` is read from `/v1/me`, which is the only channel that carries permissions
     * at all. The check is repeated on every request rather than cached in the session: a role
     * revoked a minute ago must stop working now, and `/v1/me` reads the flattened permission set
     * from the database each time.
     */
    get("/admin") {
        val session = call.requireSession(sessions) ?: return@get
        val token = call.requireAccessToken(sessions, session, client, config) ?: return@get

        val fresh = client.withBearerToken(token).me()
        session.user = fresh
        if (!fresh.permissions.contains("admin:user:read")) {
            call.respondForbidden(session, "admin:user:read")
            return@get
        }

        val users = client.withBearerToken(token).listUsers(limit = 50)
        call.respondHtml {
            page("Administration", session) {
                adminPage(
                    session,
                    users.items,
                    call.request.queryParameters["notice"],
                    call.request.queryParameters["error"],
                )
            }
        }
    }

    /** One of exactly two admin writes a bearer token can perform: it declares no reauth. */
    post("/admin/users/{id}/revoke-sessions") {
        val session = call.requireSession(sessions) ?: return@post
        val token = call.requireAccessToken(sessions, session, client, config) ?: return@post
        val userId = call.parameters["id"].orEmpty()

        val outcome = runCatching { client.withBearerToken(token).revokeUserSessions(userId) }
        call.respondRedirect(
            outcome.fold(
                onSuccess = { "/admin?notice=${"Revoked $it session(s).".urlEncoded()}" },
                onFailure = { "/admin?error=${it.describeForAdmin().urlEncoded()}" },
            ),
        )
    }

    /**
     * Deliberately wired up even though it cannot succeed from here.
     *
     * `updateUserStatus` declares `ReauthenticatedWithin`, so a bearer principal is refused with
     * `reauthentication_required`. Hiding the button would hide the lesson; the error it produces
     * is the point.
     */
    post("/admin/users/{id}/suspend") {
        val session = call.requireSession(sessions) ?: return@post
        val token = call.requireAccessToken(sessions, session, client, config) ?: return@post
        val userId = call.parameters["id"].orEmpty()

        val outcome = runCatching { client.withBearerToken(token).updateUserStatus(userId, "SUSPENDED") }
        call.respondRedirect(
            outcome.fold(
                onSuccess = { "/admin?notice=User+suspended." },
                onFailure = { "/admin?error=${it.describeForAdmin().urlEncoded()}" },
            ),
        )
    }

    // --- session inspector ----------------------------------------------------------

    get("/debug/session") {
        val session = call.requireSession(sessions) ?: return@get
        val token = call.requireAccessToken(sessions, session, client, config) ?: return@get

        val fresh = client.withBearerToken(token).me()
        session.user = fresh
        call.respondHtml { page("Session", session) { sessionPage(session, fresh, token) } }
    }
}

// --- helpers ----------------------------------------------------------------------------

private fun ApplicationCall.currentSession(sessions: SessionStore): DemoSession? =
    sessions.find(this.sessions.get<SessionCookie>()?.id)

/** Resolves the session or sends the visitor to sign in, returning null so the handler stops. */
private suspend fun ApplicationCall.requireSession(sessions: SessionStore): DemoSession? {
    val session = currentSession(sessions)
    if (session == null) {
        this.sessions.clear<SessionCookie>()
        respondRedirect("/login?return_to=${request.local.uri.urlEncoded()}")
    }
    return session
}

/**
 * A usable access token, or an end to the session.
 *
 * `null` means the refresh token was rejected — expired, revoked, or detected as reused. All
 * three are `invalid_grant` and indistinguishable, and all three mean the same thing: stop, and
 * start a new authorization.
 */
private suspend fun ApplicationCall.requireAccessToken(
    sessions: SessionStore,
    session: DemoSession,
    client: HeliumIdClient,
    config: DemoConfig,
): String? {
    val token = sessions.accessToken(session, client, config)
    if (token == null) {
        sessions.remove(session.id)
        this.sessions.clear<SessionCookie>()
        respondRedirect("/?error=session_expired")
    }
    return token
}

private suspend fun ApplicationCall.respondForbidden(session: DemoSession, permission: String) {
    respondHtml(HttpStatusCode.Forbidden) {
        page("Not permitted", session) { forbidden(session, permission) }
    }
}

private suspend fun ApplicationCall.redirectAfter(
    result: WorkspaceResult<*>,
    id: Long,
    notice: String,
) = when (result) {
    is WorkspaceResult.Ok -> respondRedirect("/documents/$id?notice=${notice.urlEncoded()}")
    is WorkspaceResult.Failed -> when (result.error) {
        WorkspaceError.NotFound -> respondRedirect("/?notice=No+such+document.")
        is WorkspaceError.Forbidden -> respondRedirect(
            "/documents/$id?error=${result.error.describe().urlEncoded()}",
        )
    }
}

private fun WorkspaceError.describe(): String = when (this) {
    WorkspaceError.NotFound -> "No such document."
    is WorkspaceError.Forbidden -> "That action needs the $required role on this document."
}

/** Turns an SDK failure into something an operator can act on. */
private fun Throwable.describeForAdmin(): String = when {
    this !is HeliumApiException -> "The identity server could not be reached."
    error is HeliumError.ReauthenticationRequired ->
        "reauthentication_required — this write needs a fresh browser session at HeliumID. " +
            "A bearer token can never satisfy it."
    error is HeliumError.Forbidden -> "forbidden — your account lacks the permission for this."
    error is HeliumError.ValidationFailed ->
        "validation_failed — HeliumID refused the change (you cannot suspend your own account)."
    else -> "${error.code} — the request was refused."
}

private fun String.urlEncoded(): String =
    java.net.URLEncoder.encode(this, Charsets.UTF_8)
