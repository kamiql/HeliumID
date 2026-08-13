package dev.kamiql.helium.demo.api

import dev.kamiql.helium.client.requireHeliumPrincipal
import dev.kamiql.helium.client.requireScope
import dev.kamiql.helium.demo.DemoConfig
import dev.kamiql.helium.demo.domain.DocumentView
import dev.kamiql.helium.demo.domain.Workspace
import dev.kamiql.helium.demo.domain.WorkspaceError
import dev.kamiql.helium.demo.domain.WorkspaceResult
import io.ktor.http.HttpStatusCode
import io.ktor.server.auth.authenticate
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import kotlinx.serialization.Serializable
import java.time.Clock

@Serializable
data class DocumentDto(
    val id: Long,
    val title: String,
    val body: String,
    val role: String,
    val updatedAt: String,
)

@Serializable
data class CreateDocumentRequest(val title: String, val body: String = "")

@Serializable
data class ApiError(val code: String, val detail: String)

/**
 * The machine-readable face of the same workspace, authorized by **scope**.
 *
 * This is axis three, and it answers a different question from the document roles in
 * `Workspace`. Those say what *this person* may do. Scopes say what *this application* was
 * allowed to do on their behalf — a distinction that only becomes visible once a third party
 * holds a token for your user.
 *
 * Both apply. A caller with `workspace:write` still cannot edit a document they only view, and a
 * document owner whose token lacks `workspace:write` still cannot write through this API.
 *
 * Verification is offline: the [dev.kamiql.helium.client.HeliumId] plugin checks the ES256
 * signature against the issuer's cached JWKS, so there is no network hop per request and no
 * availability coupling to HeliumID. The cost is revocation latency — a token revoked now keeps
 * verifying until it expires, five minutes at most. Turn on introspection in `Application.kt` if
 * that is too long for your deployment.
 *
 * Try it with the access token from `/debug/session`:
 * ```
 * curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/documents
 * ```
 */
fun Route.documentsApi(workspace: Workspace, clock: Clock) = route("/api") {

    /*
     * `authenticate("heliumid")` establishes *who* is calling; `requireScope` decides whether
     * they may. Splitting them matters: a valid token is not an authorization, and a route that
     * only authenticates has quietly granted everything the token's holder can reach.
     *
     * Note what is deliberately absent: `requireRole`. HeliumID does not put a `roles` claim in
     * access tokens — every extra claim is data leaked into every log and proxy the token passes
     * through — so `requireRole` would reject every caller. Permissions come from `/v1/me`
     * instead; see the admin section.
     */
    authenticate("heliumid") {

        requireScope(DemoConfig.SCOPE_WORKSPACE_READ) {
            get("/documents") {
                val principal = call.requireHeliumPrincipal()
                val subject = principal.userId
                    ?: return@get call.respond(
                        HttpStatusCode.Forbidden,
                        // A `client_credentials` token has no user behind it, so "documents
                        // shared with you" has no answer. Returning an empty list would imply
                        // the machine simply has none.
                        ApiError("no_user_context", "This endpoint needs a token issued for a user."),
                    )

                call.respond(workspace.visibleTo(subject).map { it.toDto() })
            }

            get("/documents/{id}") {
                val principal = call.requireHeliumPrincipal()
                val subject = principal.userId ?: return@get call.respond(
                    HttpStatusCode.Forbidden,
                    ApiError("no_user_context", "This endpoint needs a token issued for a user."),
                )
                val id = call.parameters["id"]?.toLongOrNull() ?: return@get call.respond(
                    HttpStatusCode.NotFound,
                    ApiError("not_found", "No such document."),
                )

                when (val result = workspace.read(subject, id)) {
                    is WorkspaceResult.Ok -> call.respond(result.value.toDto())
                    is WorkspaceResult.Failed -> call.respondWorkspaceError(result.error)
                }
            }
        }

        // Both scopes: writing implies reading the result back, and asking for the pair up front
        // keeps a half-authorized client from discovering the gap mid-operation.
        requireScope(DemoConfig.SCOPE_WORKSPACE_READ, DemoConfig.SCOPE_WORKSPACE_WRITE) {
            post("/documents") {
                val principal = call.requireHeliumPrincipal()
                val subject = principal.userId ?: return@post call.respond(
                    HttpStatusCode.Forbidden,
                    ApiError("no_user_context", "This endpoint needs a token issued for a user."),
                )

                val body = call.receive<CreateDocumentRequest>()
                if (body.title.isBlank()) {
                    return@post call.respond(
                        HttpStatusCode.UnprocessableEntity,
                        ApiError("validation_failed", "A title is required."),
                    )
                }

                val document = workspace.create(subject, body.title, body.body, clock.instant())
                call.respond(HttpStatusCode.Created, DocumentView(document, document.grants.getValue(subject)).toDto())
            }
        }
    }
}

private suspend fun io.ktor.server.application.ApplicationCall.respondWorkspaceError(error: WorkspaceError) {
    when (error) {
        // Same body a genuinely missing document produces: a caller must not learn that a
        // document exists by being told they may not see it.
        WorkspaceError.NotFound -> respond(HttpStatusCode.NotFound, ApiError("not_found", "No such document."))
        is WorkspaceError.Forbidden -> respond(
            HttpStatusCode.Forbidden,
            ApiError("forbidden", "This action needs the ${error.required} role on the document."),
        )
    }
}

private fun DocumentView.toDto() = DocumentDto(
    id = document.id,
    title = document.title,
    body = document.body,
    role = role.name.lowercase(),
    updatedAt = document.updatedAt.toString(),
)
