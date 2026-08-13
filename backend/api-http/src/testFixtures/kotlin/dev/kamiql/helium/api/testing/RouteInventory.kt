package dev.kamiql.helium.api.testing

import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.application.plugin
import io.ktor.server.routing.HttpMethodRouteSelector
import io.ktor.server.routing.PathSegmentConstantRouteSelector
import io.ktor.server.routing.PathSegmentOptionalParameterRouteSelector
import io.ktor.server.routing.PathSegmentParameterRouteSelector
import io.ktor.server.routing.PathSegmentTailcardRouteSelector
import io.ktor.server.routing.PathSegmentWildcardRouteSelector
import io.ktor.server.routing.RoutingNode
import io.ktor.server.routing.RoutingRoot

/**
 * One registered endpoint: a method and the path *template* it was registered under.
 *
 * The template, not a concrete path — `/v1/me/sessions/{sessionId}` rather than
 * `/v1/me/sessions/8f2c…`. That is what makes an inventory comparable across runs and what lets
 * the coverage census match a test's request back to the route it exercised.
 */
data class RouteKey(val method: HttpMethod, val path: String) : Comparable<RouteKey> {

    override fun toString(): String = "${method.value} $path"

    override fun compareTo(other: RouteKey): Int =
        compareValuesBy(this, other, { it.path }, { it.method.value })

    companion object {
        /** Parses the `METHOD /path` form written by [toString], for reading golden files back. */
        fun parse(line: String): RouteKey {
            val parts = line.trim().split(' ', limit = 2)
            require(parts.size == 2) { "not a route line: '$line'" }
            return RouteKey(HttpMethod.parse(parts[0]), parts[1])
        }
    }
}

/**
 * Enumerates every route an [Application] has actually registered.
 *
 * Read from the routing tree rather than from a hand-kept list, because a hand-kept list is a
 * second source of truth that drifts silently — and drifting is precisely the failure this is
 * here to catch. A route that exists but is undocumented and untested is invisible to review;
 * walking the tree makes it impossible to add one unnoticed.
 *
 * Registration is safe to trigger with stub dependencies: every handler body is a lambda, so
 * nothing in `heliumRoutes` dereferences its collaborators until a request arrives.
 */
object RouteInventory {

    /** Every route with a handler attached, sorted by path then method. */
    fun of(application: Application): List<RouteKey> =
        of(application.plugin(RoutingRoot))

    fun of(root: RoutingNode): List<RouteKey> =
        root.collectLeaves().mapNotNull { it.toRouteKey() }.sorted()

    /**
     * Renders the inventory as the body of `docs/api-routes.md`.
     *
     * Grouped by the top-level prefix so the document reads the way the API is organised —
     * protocol endpoints at the root, the account API under `/v1` — rather than as one flat
     * alphabetical wall.
     */
    fun toMarkdown(routes: List<RouteKey>): String = buildString {
        appendLine("# HeliumID HTTP routes")
        appendLine()
        appendLine("Generated from the Ktor routing tree by `RouteInventoryTest`. Do not edit by hand:")
        appendLine("regenerate with")
        appendLine()
        appendLine("```sh")
        appendLine("cd backend && ./gradlew :api-http:test --tests '*RouteInventoryTest*' -Dhelium.routes.write=true")
        appendLine("```")
        appendLine()
        appendLine("`:app:integrationTest` additionally fails if any route below is not exercised by an")
        appendLine("end-to-end test — see `docs/testing.md`.")
        appendLine()

        routes.groupBy { it.group() }.forEach { (group, inGroup) ->
            appendLine("## $group")
            appendLine()
            appendLine("| Method | Path |")
            appendLine("| --- | --- |")
            inGroup.forEach { appendLine("| `${it.method.value}` | `${it.path}` |") }
            appendLine()
        }

        appendLine("Total: ${routes.size} routes.")
    }

    /** Reads the route lines back out of a generated markdown document. */
    fun fromMarkdown(markdown: String): List<RouteKey> =
        ROW.findAll(markdown)
            .map { RouteKey(HttpMethod.parse(it.groupValues[1]), it.groupValues[2]) }
            .toList()
            .sorted()

    private val ROW = Regex("""^\| `([A-Z]+)` \| `(/[^`]*)` \|$""", RegexOption.MULTILINE)

    private fun RouteKey.group(): String = when {
        path.startsWith("/v1/auth") -> "Authentication (`/v1/auth`)"
        path.startsWith("/v1/me") -> "Account (`/v1/me`)"
        path.startsWith("/v1/admin") -> "Administration (`/v1/admin`)"
        path.startsWith("/oauth2") || path.startsWith("/.well-known") || path == "/userinfo" ->
            "OAuth 2.0 / OpenID Connect"
        else -> "Operational"
    }

    private fun RoutingNode.collectLeaves(): List<RoutingNode> =
        buildList {
            if (hasHandler()) add(this@collectLeaves)
            children.forEach { addAll(it.collectLeaves()) }
        }

    /**
     * Walks a node's lineage back to the root, assembling the path template.
     *
     * A node is only a route in the sense we care about if a method sits somewhere on its
     * lineage; anything else — an `install`ed plugin's interception node, a bare `route("/x")`
     * with no verb — is scaffolding and is dropped.
     */
    private fun RoutingNode.toRouteKey(): RouteKey? {
        var method: HttpMethod? = null
        val segments = ArrayDeque<String>()

        var node: RoutingNode? = this
        while (node != null) {
            when (val selector = node.selector) {
                is HttpMethodRouteSelector -> method = selector.method
                is PathSegmentConstantRouteSelector -> segments.addFirst(selector.value)
                is PathSegmentParameterRouteSelector ->
                    segments.addFirst("${selector.prefix.orEmpty()}{${selector.name}}${selector.suffix.orEmpty()}")
                is PathSegmentOptionalParameterRouteSelector -> segments.addFirst("{${selector.name}?}")
                is PathSegmentTailcardRouteSelector -> segments.addFirst("{${selector.name}...}")
                is PathSegmentWildcardRouteSelector -> segments.addFirst("*")
                // Root, trailing-slash and header selectors contribute no path segment.
                else -> Unit
            }
            node = node.parent
        }

        return method?.let { RouteKey(it, "/" + segments.joinToString("/")) }
    }
}
