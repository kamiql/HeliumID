package dev.kamiql.helium.api

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.repository.UserQuery
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.identity.AdminAssignRolesCommand
import dev.kamiql.helium.identity.AdminRevokeUserSessionsCommand
import dev.kamiql.helium.identity.AdminUpdateUserStatusCommand
import dev.kamiql.helium.oauth.DeleteClientCommand
import dev.kamiql.helium.oauth.DeleteScopeCommand
import dev.kamiql.helium.oauth.RegisterClientCommand
import dev.kamiql.helium.oauth.RotateClientSecretCommand
import dev.kamiql.helium.oauth.UpdateClientCommand
import dev.kamiql.helium.oauth.UpsertScopeCommand
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.patch
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.route

/**
 * `/v1/admin` — the surface the admin UI talks to.
 *
 * Read endpoints check the permission inline (they change nothing, so there is no flow to
 * declare it on); every write goes through a flow that declares the permission *and* the
 * reauthentication requirement, so the policy is not duplicated here.
 */
fun Route.adminRoutes(dependencies: HeliumApiDependencies) = route("/admin") {

    // --- users ---------------------------------------------------------------

    get("/users") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_USER_READ)) return@get

        val query = UserQuery(
            term = call.request.queryParameters["q"],
            status = call.request.queryParameters["status"]
                ?.let { runCatching { UserStatus.valueOf(it) }.getOrNull() },
            role = call.request.queryParameters["role"],
            limit = call.request.queryParameters["limit"]?.toIntOrNull()?.coerceIn(1, 200) ?: 50,
            offset = call.request.queryParameters["offset"]?.toLongOrNull()?.coerceAtLeast(0) ?: 0,
        )
        val page = dependencies.users.search(query)
        call.respond(
            PageResponse(
                items = page.items.map { user ->
                    AdminUserResponse(
                        id = user.id.value.toString(),
                        username = user.username.display,
                        email = user.primaryEmail.display,
                        emailVerified = user.isEmailVerified,
                        firstName = user.firstName,
                        lastName = user.lastName,
                        status = user.status.name,
                        roles = dependencies.roles.rolesOf(user.id).sorted(),
                        createdAt = user.createdAt.toString(),
                        updatedAt = user.updatedAt.toString(),
                    )
                },
                total = page.total,
                limit = page.limit,
                offset = page.offset,
            ),
        )
    }

    get("/users/{userId}") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_USER_READ)) return@get
        val userId = call.parameters["userId"]?.let(UserId::parse)
        val user = userId?.let { dependencies.users.findById(it) }
        if (user == null) {
            call.respondProblem(AuthError.NotFound)
            return@get
        }
        call.respond(
            AdminUserResponse(
                id = user.id.value.toString(),
                username = user.username.display,
                email = user.primaryEmail.display,
                emailVerified = user.isEmailVerified,
                firstName = user.firstName,
                lastName = user.lastName,
                status = user.status.name,
                roles = dependencies.roles.rolesOf(user.id).sorted(),
                createdAt = user.createdAt.toString(),
                updatedAt = user.updatedAt.toString(),
            ),
        )
    }

    put("/users/{userId}/status") {
        if (!call.enforceCsrf(dependencies)) return@put
        val userId = call.parameters["userId"]?.let(UserId::parse)
        val body = call.receive<UpdateUserStatusRequest>()
        val status = runCatching { UserStatus.valueOf(body.status) }.getOrNull()
        if (userId == null || status == null) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("status" to "invalid")))
            return@put
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.adminFlows.updateUserStatus,
            command = AdminUpdateUserStatusCommand(userId, status),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    put("/users/{userId}/roles") {
        if (!call.enforceCsrf(dependencies)) return@put
        val userId = call.parameters["userId"]?.let(UserId::parse)
        val body = call.receive<AssignRolesRequest>()
        if (userId == null) {
            call.respondProblem(AuthError.NotFound)
            return@put
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.adminFlows.assignRoles,
            command = AdminAssignRolesCommand(userId, body.roles.toSet()),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    post("/users/{userId}/revoke-sessions") {
        if (!call.enforceCsrf(dependencies)) return@post
        val userId = call.parameters["userId"]?.let(UserId::parse)
        if (userId == null) {
            call.respondProblem(AuthError.NotFound)
            return@post
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.adminFlows.revokeUserSessions,
            command = AdminRevokeUserSessionsCommand(userId),
            context = context,
        )
        call.respondFlow(result) { count -> call.respond(mapOf("revoked" to count)) }
    }

    get("/users/{userId}/sessions") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_USER_READ)) return@get
        val userId = call.parameters["userId"]?.let(UserId::parse)
        if (userId == null) {
            call.respondProblem(AuthError.NotFound)
            return@get
        }
        val (_, context) = call.heliumContext(dependencies)
        call.respond(
            dependencies.sessions.listActiveForUser(userId, context.now).map { it.toResponse(current = false) },
        )
    }

    // --- roles ------------------------------------------------------------------

    get("/roles") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_ROLE_READ)) return@get
        call.respond(dependencies.roles.listRoles().map { it.toResponse() })
    }

    get("/permissions") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_ROLE_READ)) return@get
        call.respond(Permission.ALL.map { it.value }.sorted())
    }

    put("/roles/{name}") {
        if (!call.enforceCsrf(dependencies)) return@put
        if (!call.requirePermission(dependencies, Permission.ADMIN_ROLE_WRITE)) return@put
        val name = call.parameters["name"].orEmpty()
        val body = call.receive<UpsertRoleRequest>()

        val existing = dependencies.roles.findRole(name)
        if (existing?.builtIn == true) {
            // Built-in roles are referenced by code; letting an administrator strip
            // ADMINISTRATOR's permissions is a one-click lockout.
            call.respondProblem(AuthError.Conflict)
            return@put
        }
        val known = Permission.ALL.map { it.value }.toSet()
        val unknown = body.permissions.toSet() - known
        if (unknown.isNotEmpty()) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("permissions" to "unknown")))
            return@put
        }

        val saved = dependencies.roles.upsertRole(
            Role(
                name = name,
                description = body.description,
                color = body.color,
                permissions = body.permissions.map(::Permission).toSet(),
                builtIn = false,
            ),
        )
        call.respond(saved.toResponse())
    }

    delete("/roles/{name}") {
        if (!call.enforceCsrf(dependencies)) return@delete
        if (!call.requirePermission(dependencies, Permission.ADMIN_ROLE_WRITE)) return@delete
        val name = call.parameters["name"].orEmpty()
        if (dependencies.roles.deleteRole(name)) {
            call.respond(HttpStatusCode.NoContent)
        } else {
            call.respondProblem(AuthError.NotFound)
        }
    }

    // --- OAuth clients --------------------------------------------------------------

    get("/clients") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_CLIENT_READ)) return@get
        val limit = call.request.queryParameters["limit"]?.toIntOrNull()?.coerceIn(1, 200) ?: 50
        val offset = call.request.queryParameters["offset"]?.toLongOrNull()?.coerceAtLeast(0) ?: 0
        val page = dependencies.clients.list(limit, offset)
        call.respond(PageResponse(page.items.map { it.toResponse() }, page.total, page.limit, page.offset))
    }

    get("/clients/{clientId}") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_CLIENT_READ)) return@get
        val client = call.parameters["clientId"]
            ?.let { runCatching { ClientId(it) }.getOrNull() }
            ?.let { dependencies.clients.findById(it) }
        if (client == null) {
            call.respondProblem(AuthError.NotFound)
            return@get
        }
        call.respond(client.toResponse())
    }

    get("/scopes") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_CLIENT_READ)) return@get
        call.respond(dependencies.clients.listScopes().sortedBy { it.name }.map { it.toResponse() })
    }

    /*
     * Scope writes go through a flow rather than checking inline like the role routes below.
     * The scope catalogue is what clients are registered against and what the consent screen
     * reads its wording from, so these changes must carry the same reauthentication requirement
     * and the same audit trail as client registration — inline checks would give them neither.
     */
    put("/scopes/{name}") {
        if (!call.enforceCsrf(dependencies)) return@put
        val name = call.parameters["name"].orEmpty()
        val body = call.receive<UpsertScopeRequest>()

        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.clientAdminFlows.upsertScope,
            command = UpsertScopeCommand(
                name = name,
                description = body.description,
                implicit = body.implicit,
            ),
            context = context,
        )
        call.respondFlow(result) { scope -> call.respond(scope.toResponse()) }
    }

    delete("/scopes/{name}") {
        if (!call.enforceCsrf(dependencies)) return@delete
        val name = call.parameters["name"].orEmpty()

        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.clientAdminFlows.deleteScope,
            command = DeleteScopeCommand(name),
            context = context,
        )
        call.respondFlow(result) { call.respond(HttpStatusCode.NoContent) }
    }

    post("/clients") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<RegisterClientRequest>()
        val type = runCatching { ClientType.valueOf(body.type) }.getOrNull()
        val grants = body.grantTypes.mapNotNull(GrantType::parse).toSet()
        if (type == null || grants.size != body.grantTypes.size) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("type" to "invalid")))
            return@post
        }

        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.clientAdminFlows.register,
            command = RegisterClientCommand(
                clientId = body.clientId,
                name = body.name,
                type = type,
                redirectUris = body.redirectUris.toSet(),
                scopes = body.scopes.toSet(),
                grantTypes = grants,
                audiences = body.audiences.toSet(),
                skipConsent = body.skipConsent,
            ),
            context = context,
        )
        // 201 with the secret: this is the only response that will ever contain it.
        call.respondFlow(result) { issued ->
            call.respond(
                HttpStatusCode.Created,
                ClientSecretResponse(issued.clientId.value, issued.secret, issued.rotatedAt.toString()),
            )
        }
    }

    patch("/clients/{clientId}") {
        if (!call.enforceCsrf(dependencies)) return@patch
        val clientId = call.parameters["clientId"]?.let { runCatching { ClientId(it) }.getOrNull() }
        if (clientId == null) {
            call.respondProblem(AuthError.NotFound)
            return@patch
        }
        val body = call.receive<UpdateClientRequest>()
        val grants = body.grantTypes?.mapNotNull(GrantType::parse)?.toSet()
        if (body.grantTypes != null && grants?.size != body.grantTypes.size) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("grant_types" to "invalid")))
            return@patch
        }

        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.clientAdminFlows.update,
            command = UpdateClientCommand(
                clientId = clientId,
                name = body.name,
                redirectUris = body.redirectUris?.toSet(),
                scopes = body.scopes?.toSet(),
                grantTypes = grants,
                audiences = body.audiences?.toSet(),
                skipConsent = body.skipConsent,
                enabled = body.enabled,
            ),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    post("/clients/{clientId}/rotate-secret") {
        if (!call.enforceCsrf(dependencies)) return@post
        val clientId = call.parameters["clientId"]?.let { runCatching { ClientId(it) }.getOrNull() }
        if (clientId == null) {
            call.respondProblem(AuthError.NotFound)
            return@post
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.clientAdminFlows.rotateSecret,
            command = RotateClientSecretCommand(clientId),
            context = context,
        )
        call.respondFlow(result) { issued ->
            call.respond(ClientSecretResponse(issued.clientId.value, issued.secret, issued.rotatedAt.toString()))
        }
    }

    delete("/clients/{clientId}") {
        if (!call.enforceCsrf(dependencies)) return@delete
        val clientId = call.parameters["clientId"]?.let { runCatching { ClientId(it) }.getOrNull() }
        if (clientId == null) {
            call.respondProblem(AuthError.NotFound)
            return@delete
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.clientAdminFlows.delete,
            command = DeleteClientCommand(clientId),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    // --- audit --------------------------------------------------------------------

    get("/audit") {
        if (!call.requirePermission(dependencies, Permission.ADMIN_AUDIT_READ)) return@get
        val page = dependencies.auditQuery.query(
            subjectUserId = call.request.queryParameters["user_id"]?.let(UserId::parse),
            eventType = call.request.queryParameters["event_type"],
            limit = call.request.queryParameters["limit"]?.toIntOrNull()?.coerceIn(1, 500) ?: 100,
            offset = call.request.queryParameters["offset"]?.toLongOrNull()?.coerceAtLeast(0) ?: 0,
        )
        call.respond(PageResponse(page.items, page.total, page.limit, page.offset))
    }
}

/**
 * Permission gate for read-only admin endpoints.
 *
 * Writes do **not** use this: they declare the permission on the flow, alongside the
 * reauthentication requirement, so the whole policy for a mutation is in one place.
 */
private suspend fun ApplicationCall.requirePermission(
    dependencies: HeliumApiDependencies,
    permission: Permission,
): Boolean {
    val (actor, _) = heliumContext(dependencies)
    if (actor.has(permission)) return true
    respondProblem(
        if (actor is dev.kamiql.helium.domain.policy.Principal.Anonymous) AuthError.AuthenticationRequired
        else AuthError.Forbidden(permission.value),
    )
    return false
}
