package dev.kamiql.helium.client

import io.ktor.server.application.ApplicationCall
import io.ktor.server.auth.principal
import io.ktor.server.routing.RoutingContext
import java.time.Instant

/**
 * The caller of an authenticated request, as proven by a HeliumID access token.
 *
 * Everything here comes from claims that were covered by the token's ES256 signature. Nothing
 * is looked up, inferred or defaulted — if a field is `null`, the claim was absent, and you
 * should treat that as "unknown", never as "no".
 *
 * Access tokens are deliberately thin (concept §4.2): no email, no display name, and normally
 * no roles. A token is a bearer credential that lands in logs and proxies, and every extra
 * claim is data leaked everywhere it travels. When you need profile data, call
 * [HeliumIdClient.userInfo] or your own store, keyed on [userId].
 */
public data class HeliumPrincipal(

    /** The `sub` claim: the user id for user tokens, the client id for machine tokens. */
    public val subject: String,

    /**
     * The authenticated user, or `null` for a `client_credentials` token.
     *
     * Use this rather than [subject] whenever you mean "a person": a machine token's subject is
     * a client id, and treating the two as the same namespace is how a service account ends up
     * owning a user's rows.
     */
    public val userId: String?,

    /** The `client_id` claim: which registered application obtained this token. */
    public val clientId: String?,

    /** Granted scopes, parsed from the space-delimited `scope` claim. */
    public val scopes: Set<String>,

    /**
     * Roles carried in the token, if the deployment puts them there.
     *
     * Normally **empty**: HeliumID does not mint roles into access tokens by default. Prefer
     * [scopes] for authorization decisions and treat roles as an opt-in extension — see
     * [requireRole].
     */
    public val roles: Set<String>,

    /**
     * `amr` — how the subject actually authenticated, e.g. `pwd`, `otp`.
     *
     * This is the evidence; [authenticationContextClass] is the summary.
     */
    public val authenticationMethods: Set<String>,

    /**
     * `acr` — `pwd` for a single factor, `mfa` when a second factor was presented.
     *
     * Gate step-up-sensitive operations on this rather than re-deriving it from
     * [authenticationMethods].
     */
    public val authenticationContextClass: String?,

    /** `sid` — the browser session that produced this token, when there was one. */
    public val sessionId: String?,

    /** `jti` — the token's unique id. Safe to log; it is an identifier, not a credential. */
    public val tokenId: String,

    /** `aud` — the audiences this token was minted for. Already validated against your own. */
    public val audience: Set<String>,

    /** `iat`, when present. */
    public val issuedAt: Instant?,

    /** `exp`. Already checked, but useful for cache lifetimes that must not outlive the token. */
    public val expiresAt: Instant,
) {

    /** True for a `client_credentials` token: a machine with no user behind it. */
    public val isServiceClient: Boolean get() = userId == null

    /** True when a second factor was presented for this authentication. */
    public val usedMultiFactor: Boolean get() = authenticationContextClass == "mfa"

    /** Exact scope match. Scopes are opaque strings; no prefix or wildcard logic is implied. */
    public fun hasScope(scope: String): Boolean = scope in scopes

    /** True when *every* named scope is present. */
    public fun hasAllScopes(vararg required: String): Boolean = required.all { it in scopes }

    /** True when *any* named scope is present. */
    public fun hasAnyScope(vararg accepted: String): Boolean = accepted.any { it in scopes }

    /** Exact role match. See [roles] for why this is usually not what you want. */
    public fun hasRole(role: String): Boolean = role in roles

    /** True when *any* named role is present. */
    public fun hasAnyRole(vararg accepted: String): Boolean = accepted.any { it in roles }

    /**
     * Redacted deliberately.
     *
     * Not because the fields are secret — they are claims, not credentials — but because a
     * principal dumped into a log line is the fastest route to an unreviewed PII sink. Log
     * [tokenId] and [subject] explicitly if you need them.
     */
    override fun toString(): String =
        "HeliumPrincipal(subject=$subject, clientId=$clientId, jti=$tokenId)"
}

/**
 * The verified caller, or `null` when the route allows anonymous access.
 *
 * Inside `authenticate("heliumid") { ... }` this is non-null by construction — the provider
 * challenges before the handler runs — so `call.heliumPrincipal()!!` is honest there. It is
 * nullable for `authenticate(optional = true)` routes.
 *
 * ```kotlin
 * get("/orders") {
 *     val principal = call.heliumPrincipal() ?: error("route is inside authenticate(\"heliumid\")")
 *     call.respond(orders.forUser(principal.userId!!))
 * }
 * ```
 */
public fun ApplicationCall.heliumPrincipal(): HeliumPrincipal? = principal()

/** Same, for route handlers that would rather not spell out `call.`. */
public fun RoutingContext.heliumPrincipal(): HeliumPrincipal? = call.heliumPrincipal()

/**
 * The verified caller, or a failure.
 *
 * Use inside a mandatory `authenticate("heliumid")` block when you want the impossible case to
 * be loud rather than a nullable you silently `?:` away.
 *
 * @throws IllegalStateException if the route is not behind the HeliumID provider.
 */
public fun ApplicationCall.requireHeliumPrincipal(): HeliumPrincipal = checkNotNull(heliumPrincipal()) {
    "No HeliumPrincipal on this call: the route is not inside authenticate(\"heliumid\")"
}
