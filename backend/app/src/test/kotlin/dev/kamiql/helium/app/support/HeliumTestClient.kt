package dev.kamiql.helium.app.support

import dev.kamiql.helium.api.CSRF_HEADER
import dev.kamiql.helium.api.testing.RouteKey
import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.plugins.cookies.cookies
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpMethod
import io.ktor.http.Url
import io.ktor.http.encodeURLPathPart
import io.ktor.client.plugins.plugin
import java.util.concurrent.ConcurrentHashMap

/**
 * The HTTP client the end-to-end suite talks through.
 *
 * Three jobs, all of which every test would otherwise repeat:
 *
 *  1. **Requests are made against the route template, not a concrete path.** A test asks for
 *     `"/v1/me/sessions/{sessionId}"` with the id as a parameter, and the client substitutes.
 *     That is what makes the coverage census exact — the alternative, matching a concrete path
 *     back to a template afterwards, is a second routing implementation that can disagree with
 *     Ktor's, and a census built on a heuristic reports coverage it cannot prove.
 *  2. **CSRF is attached automatically.** The double-submit token is a property of the transport,
 *     not of the behaviour under test; a hundred tests echoing the cookie by hand would be a
 *     hundred chances to test a `403` by accident. Tests that want to prove the CSRF check works
 *     use [HeliumTestScope.rawHttp], which does none of this.
 *  3. **Every request is recorded** into [RouteCensus].
 */
class HeliumTestClient(private val delegate: HttpClient) {

    suspend fun get(
        template: String,
        vararg params: Pair<String, String>,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse = request(HttpMethod.Get, template, *params, block = block)

    suspend fun post(
        template: String,
        vararg params: Pair<String, String>,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse = request(HttpMethod.Post, template, *params, block = block)

    suspend fun put(
        template: String,
        vararg params: Pair<String, String>,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse = request(HttpMethod.Put, template, *params, block = block)

    suspend fun patch(
        template: String,
        vararg params: Pair<String, String>,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse = request(HttpMethod.Patch, template, *params, block = block)

    suspend fun delete(
        template: String,
        vararg params: Pair<String, String>,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse = request(HttpMethod.Delete, template, *params, block = block)

    /**
     * Issues one request against [template], recording it as exercised.
     *
     * The route is recorded *before* the call rather than after, and regardless of the status
     * that comes back. A route that answers `403` was still reached, and a census that only
     * counted successes would quietly stop counting the negative tests — which are the ones
     * CLAUDE.md asks for most.
     */
    suspend fun request(
        method: HttpMethod,
        template: String,
        vararg params: Pair<String, String>,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        RouteCensus.record(RouteKey(method, template))

        val path = template.substitute(params.toMap())
        return delegate.request(path) {
            this.method = method
            attachCsrf(method)
            block()
        }
    }

    /**
     * Echoes the CSRF cookie back in the header, as the SPA does.
     *
     * Skipped when there is no cookie yet: a suite that has not bootstrapped a session should see
     * the server's own `csrf:token-missing` rejection rather than a header invented here.
     */
    private suspend fun HttpRequestBuilder.attachCsrf(method: HttpMethod) {
        if (method in SAFE_METHODS) return
        val name = HeliumTestApp.components.httpSecurity.csrfCookieName
        delegate.cookies(ORIGIN).firstOrNull { it.name == name }?.let { header(CSRF_HEADER, it.value) }
    }

    /**
     * Fills a route template in.
     *
     * Every placeholder must be supplied and every parameter must be used. Both directions are
     * checked because both mistakes end the same way — a request to a path that matches no route,
     * producing a `404` a test then reads as a meaningful answer.
     */
    private fun String.substitute(params: Map<String, String>): String {
        var path = this
        params.forEach { (name, value) ->
            val placeholder = "{$name}"
            require(path.contains(placeholder)) { "route template '$this' has no '$placeholder'" }
            path = path.replace(placeholder, value.encodeURLPathPart())
        }
        require(!PLACEHOLDER.containsMatchIn(path)) {
            "route template '$this' still has unfilled parameters: " +
                PLACEHOLDER.findAll(path).joinToString { it.value }
        }
        return path
    }

    private companion object {
        /** `testApplication` serves on this origin; the cookie jar is keyed by it. */
        val ORIGIN = Url("http://localhost/")
        val SAFE_METHODS = setOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options)
        val PLACEHOLDER = Regex("""\{[^}]+}""")
    }
}

/** Cookie access needs the plugin; `client.cookies(url)` is the plugin's own extension. */
private suspend fun HttpClient.cookies(url: Url) = plugin(HttpCookies).get(url)

/**
 * Which routes the suite has actually reached, for the whole JVM.
 *
 * A single mutable object shared across test classes, because the question it answers — *is
 * every registered route exercised by something?* — is a property of the suite, not of any one
 * class. [RouteCoverageTest] reads it once everything else has run.
 *
 * Never reset between tests. Truncating the database between cases is about isolating state;
 * coverage is cumulative by definition.
 */
object RouteCensus {

    private val exercised = ConcurrentHashMap.newKeySet<RouteKey>()

    fun record(route: RouteKey) {
        exercised.add(route)
    }

    fun exercised(): Set<RouteKey> = exercised.toSet()
}
