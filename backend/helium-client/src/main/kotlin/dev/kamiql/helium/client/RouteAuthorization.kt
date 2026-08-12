package dev.kamiql.helium.client

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createRouteScopedPlugin
import io.ktor.server.application.isHandled
import io.ktor.server.auth.AuthenticationChecked
import io.ktor.server.routing.Route
import io.ktor.server.routing.RouteSelector
import io.ktor.server.routing.RouteSelectorEvaluation
import io.ktor.server.routing.RoutingResolveContext

/**
 * Restricts the routes inside to callers whose token carries **all** of [scopes].
 *
 * Scopes are the primary authorization signal for HeliumID access tokens: they are what the
 * client was actually granted, they survive in the token, and they are checked without a
 * database. Prefer them over roles.
 *
 * ```kotlin
 * authenticate("heliumid") {
 *     requireScope("orders:read") {
 *         get("/orders") { /* ... */ }
 *     }
 *     requireScope("orders:read", "orders:write") {
 *         post("/orders") { /* ... */ }   // needs both
 *     }
 * }
 * ```
 *
 * Denials answer `403` with the same `forbidden` problem+json code the identity server uses, so
 * clients need one error branch rather than two.
 *
 * Must be nested inside `authenticate("heliumid")`. Outside it there is no principal, and the
 * check denies everything — deliberately, rather than silently letting traffic through.
 *
 * @param scopes every scope the caller must hold. An empty list is a programming error.
 * @throws IllegalArgumentException if [scopes] is empty.
 */
public fun Route.requireScope(vararg scopes: String, build: Route.() -> Unit): Route {
    require(scopes.isNotEmpty()) { "requireScope needs at least one scope" }
    val required = scopes.toSet()
    val route = createChild(AuthorizationRouteSelector("scopes=${required.sorted()}"))
    route.install(HeliumAuthorizationPlugin) {
        requiredScopes = required
        requirement = "scope:${required.sorted().joinToString(" ")}"
    }
    route.build()
    return route
}

/**
 * Restricts the routes inside to callers whose token carries **any** of [roles].
 *
 * Any rather than all: roles model "who someone is", and requiring a user to hold every role at
 * once is almost never the intent. Use nested [requireRole] blocks if you really need a
 * conjunction.
 *
 * ```kotlin
 * authenticate("heliumid") {
 *     requireRole("ADMINISTRATOR", "SUPPORT") {
 *         get("/admin/tickets") { /* ... */ }
 *     }
 * }
 * ```
 *
 * **Roles are not in HeliumID access tokens by default.** An access token carries the concept
 * §4.2 claim set and no roles, because every extra claim is data leaked to every log and proxy
 * the token passes through. This helper therefore denies everything unless the issuer is
 * configured to emit a roles claim and [HeliumIdConfig.rolesClaim] names it. If you are
 * authorizing a machine-to-machine call, you want [requireScope].
 *
 * @param roles any one of which admits the caller.
 * @throws IllegalArgumentException if [roles] is empty.
 */
public fun Route.requireRole(vararg roles: String, build: Route.() -> Unit): Route {
    require(roles.isNotEmpty()) { "requireRole needs at least one role" }
    val accepted = roles.toSet()
    val route = createChild(AuthorizationRouteSelector("roles=${accepted.sorted()}"))
    route.install(HeliumAuthorizationPlugin) {
        acceptedRoles = accepted
        requirement = "role:${accepted.sorted().joinToString(" ")}"
    }
    route.build()
    return route
}

/** Configuration for one authorization gate. */
public class HeliumAuthorizationConfig {

    /** Scopes the caller must hold, all of them. */
    internal var requiredScopes: Set<String> = emptySet()

    /** Roles the caller may hold, any of them. */
    internal var acceptedRoles: Set<String> = emptySet()

    /** Human-readable requirement, reported to the caller so a 403 is actionable. */
    internal var requirement: String = ""
}

/**
 * The gate itself.
 *
 * It runs on the [AuthenticationChecked] hook — after the provider has resolved a principal and
 * before the route handler. Responding here marks the call handled, and Ktor's router skips the
 * handler for a handled call, so a denial cannot fall through to the endpoint.
 */
private val HeliumAuthorizationPlugin = createRouteScopedPlugin(
    name = "HeliumAuthorization",
    createConfiguration = ::HeliumAuthorizationConfig,
) {
    val requiredScopes = pluginConfig.requiredScopes
    val acceptedRoles = pluginConfig.acceptedRoles
    val requirement = pluginConfig.requirement

    on(AuthenticationChecked) { call ->
        if (call.isHandled) return@on
        val principal = call.heliumPrincipal()

        if (principal == null) {
            // Either the route is not behind `authenticate("heliumid")`, or authentication is
            // optional here. Both are a denial: an authorization check with nothing to check
            // must never be a pass.
            call.respondHeliumProblem(
                status = HttpStatusCode.Unauthorized,
                code = "auth_required",
                detail = "Authentication is required.",
                bearerError = "invalid_request",
                realm = "identity",
            )
            return@on
        }

        val permitted = when {
            requiredScopes.isNotEmpty() -> requiredScopes.all { it in principal.scopes }
            acceptedRoles.isNotEmpty() -> acceptedRoles.any { it in principal.roles }
            else -> true
        }

        if (!permitted) {
            // The requirement is named but the caller's own scopes are not echoed back: telling
            // a caller exactly what they are missing is a map of the authorization model.
            call.respondHeliumProblem(
                status = HttpStatusCode.Forbidden,
                code = "forbidden",
                detail = "You do not have permission to perform this action. Required: $requirement.",
                bearerError = null,
                realm = "identity",
            )
        }
    }
}

/**
 * A transparent selector, so wrapping routes in an authorization block does not change routing
 * priority or the matched path.
 *
 * The label exists purely so route introspection and logs show *why* a node is there.
 */
private class AuthorizationRouteSelector(private val label: String) : RouteSelector() {

    override suspend fun evaluate(
        context: RoutingResolveContext,
        segmentIndex: Int,
    ): RouteSelectorEvaluation = RouteSelectorEvaluation.Transparent

    override fun toString(): String = "(authorize $label)"

    override fun equals(other: Any?): Boolean =
        other is AuthorizationRouteSelector && other.label == label

    override fun hashCode(): Int = label.hashCode()
}
