package dev.kamiql.helium.client

import io.ktor.client.HttpClient
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.auth.HttpAuthHeader
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationPlugin
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.auth.AuthenticationContext
import io.ktor.server.auth.AuthenticationFailedCause
import io.ktor.server.auth.AuthenticationProvider
import io.ktor.server.auth.authentication
import io.ktor.server.auth.parseAuthorizationHeader
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Makes HeliumID the identity service for this Ktor application.
 *
 * Installing the plugin registers a bearer [AuthenticationProvider] (named `heliumid` by
 * default) that verifies HeliumID access tokens. By default verification is **offline**: the
 * issuer's JWKS is fetched and cached, and every request is checked locally against it with no
 * network hop and no availability coupling to the identity server.
 *
 * Usage:
 * ```kotlin
 * install(HeliumId) {
 *     issuer = "https://id.example"
 *     audience = "orders-api"                 // this service's own audience — validate it
 *     jwks { cacheFor = 10.minutes }          // offline ES256 verification, the default
 *     introspection { enabled = true }        // opt-in, for instant revocation
 * }
 *
 * routing {
 *     authenticate("heliumid") {
 *         get("/orders") {
 *             val principal = call.requireHeliumPrincipal()
 *             call.respond(orders.forUser(principal.userId!!))
 *         }
 *         requireScope("orders:read") {
 *             get("/orders/{id}") { /* ... */ }
 *         }
 *         requireRole("ADMINISTRATOR") {
 *             delete("/orders/{id}") { /* ... */ }
 *         }
 *     }
 * }
 * ```
 *
 * ### What is validated
 * `iss` (exact), `aud` (exact, when [HeliumIdConfig.audience] is set), `exp`, `nbf`, and an
 * ES256 signature over a key resolved by `kid` from the issuer's JWKS. The algorithm set is
 * pinned to ES256 alone, so `alg: none` and the HMAC-with-the-public-key confusion attack both
 * fail at key selection rather than at signature comparison.
 *
 * ### What is not
 * Authorization. A valid token says who is calling, not what they may do. Use [requireScope],
 * [requireRole], or your own check on [HeliumPrincipal].
 *
 * ### Failure responses
 * A missing or unusable token produces `401` with
 * `WWW-Authenticate: Bearer realm="identity", error="invalid_token"` and an RFC 9457
 * `application/problem+json` body whose `code` matches the identity server's own catalogue, so
 * a client handles errors from your service and from HeliumID with the same code.
 */
public val HeliumId: ApplicationPlugin<HeliumIdConfig> =
    createApplicationPlugin("HeliumId", ::HeliumIdConfig) {
        val settings = pluginConfig.validated()
        val verifier = settings.buildVerifier()

        // `authentication {}` installs the Authentication plugin if it is absent and configures
        // it otherwise, so `install(HeliumId)` composes with an application that already has
        // other providers registered.
        application.authentication {
            register(
                HeliumAuthenticationProvider(
                    config = HeliumAuthenticationProvider.Config(settings.providerName),
                    verifier = verifier,
                    realm = settings.realm,
                ),
            )
        }
    }

/**
 * Configuration for [HeliumId].
 *
 * [issuer] is the only required value. [audience] is optional but strongly recommended: without
 * it, any token minted by this issuer for any of its clients is accepted here, which is token
 * substitution waiting to happen.
 */
public class HeliumIdConfig {

    /**
     * The identity server's issuer URL, e.g. `https://id.example`.
     *
     * Must match the `iss` claim exactly — no trailing slash unless the issuer uses one. This
     * is also the base for the default JWKS and introspection endpoints.
     */
    public var issuer: String = ""

    /**
     * This service's audience, matched exactly against the token's `aud`.
     *
     * Leave `null` only if you genuinely accept any token from this issuer. Every deployment
     * that does not is one compromised sibling service away from replaying its tokens here.
     */
    public var audience: String? = null

    /**
     * Name of the registered authentication provider.
     *
     * The name you pass to `authenticate(...)`. Change it only if it collides with an existing
     * provider in the same application.
     */
    public var providerName: String = "heliumid"

    /** Realm advertised in the `WWW-Authenticate` challenge. */
    public var realm: String = "identity"

    /**
     * Tolerance for clock drift between this service and the identity server.
     *
     * Applied to `exp` and `nbf`. Keep it small: it directly extends the usable life of an
     * expired token.
     */
    public var clockSkew: Duration = 30.seconds

    /**
     * Claim to read roles from, when the deployment mints them into access tokens.
     *
     * HeliumID does not by default — an access token is a bearer credential that travels
     * through logs and proxies, and roles are not part of the §4.2 claim set. [requireRole]
     * therefore denies everything unless you configure the issuer to emit this claim.
     */
    public var rolesClaim: String = "roles"

    internal val jwks: JwksConfig = JwksConfig()
    internal val introspection: IntrospectionConfig = IntrospectionConfig()

    /**
     * Tunes offline JWKS verification — the default mode.
     *
     * ```kotlin
     * jwks {
     *     cacheFor = 10.minutes
     *     rateLimitFor = 30.seconds
     * }
     * ```
     */
    public fun jwks(configure: JwksConfig.() -> Unit) {
        jwks.configure()
    }

    /**
     * Enables and configures RFC 7662 introspection.
     *
     * ```kotlin
     * introspection {
     *     enabled = true
     *     clientId = "orders-api"
     *     clientSecret = System.getenv("HELIUM_CLIENT_SECRET")
     *     cacheFor = 10.seconds
     * }
     * ```
     */
    public fun introspection(configure: IntrospectionConfig.() -> Unit) {
        introspection.configure()
    }

    /** Fails fast at install time rather than on the first request. */
    internal fun validated(): HeliumIdSettings {
        require(issuer.isNotBlank()) { "HeliumId: `issuer` is required" }
        require(issuer.startsWith("https://") || issuer.startsWith("http://")) {
            "HeliumId: `issuer` must be an absolute http(s) URL"
        }
        val base = issuer.trimEnd('/')
        if (introspection.enabled) {
            require(introspection.clientId.isNotBlank() && introspection.clientSecret.isNotBlank()) {
                "HeliumId: introspection requires `clientId` and `clientSecret` — the endpoint " +
                    "reads other parties' tokens and will not answer an unauthenticated caller"
            }
        }
        return HeliumIdSettings(
            issuer = base,
            audience = audience,
            providerName = providerName,
            realm = realm,
            clockSkew = clockSkew,
            rolesClaim = rolesClaim,
            jwksUri = jwks.uri ?: "$base/.well-known/jwks.json",
            jwks = jwks,
            introspection = introspection,
            introspectionBaseUrl = introspection.baseUrl ?: base,
        )
    }
}

/** Offline JWKS verification settings. */
public class JwksConfig {

    /** Override the JWKS URL. Defaults to `$issuer/.well-known/jwks.json`. */
    public var uri: String? = null

    /**
     * How long a fetched key set is served without re-fetching.
     *
     * The identity server's key rotation keeps an overlap window precisely so verifier caches
     * stay valid; ten minutes is comfortably inside it. Longer is fine and cheaper; shorter
     * mostly just adds load.
     */
    public var cacheFor: Duration = 10.minutes

    /**
     * How long other threads wait while one of them refreshes an expired cache.
     *
     * Stops a thundering herd on the JWKS endpoint at expiry.
     */
    public var refreshTimeout: Duration = 15.seconds

    /**
     * Minimum interval between refreshes triggered by an unknown `kid`.
     *
     * Without this, a stream of tokens carrying forged key ids turns every request into a JWKS
     * fetch — an amplified denial of service pointed at the identity server.
     */
    public var rateLimitFor: Duration = 30.seconds

    /** TCP connect budget for the JWKS fetch. */
    public var connectTimeout: Duration = 2.seconds

    /** Read budget for the JWKS fetch. */
    public var readTimeout: Duration = 2.seconds

    /** Hard cap on the JWKS document size, in bytes. A defence against a hostile response. */
    public var sizeLimit: Int = 64 * 1024
}

/**
 * RFC 7662 introspection settings.
 *
 * See the module README for when this is worth its cost.
 */
public class IntrospectionConfig {

    /**
     * Turn introspection on.
     *
     * When enabled, the signature is still checked offline first — that rejects malformed and
     * forged tokens without spending a round trip — and introspection then confirms the token
     * has not been revoked.
     */
    public var enabled: Boolean = false

    /** Override the introspection base URL. Defaults to the issuer. */
    public var baseUrl: String? = null

    /** Client id this resource server authenticates with. Introspection is not public. */
    public var clientId: String = ""

    /**
     * Client secret.
     *
     * Read it from your secret manager. It is never logged by this SDK and must never be
     * committed.
     */
    public var clientSecret: String = ""

    /**
     * How long an introspection answer is reused.
     *
     * This is your revocation latency: a token revoked now keeps working for at most this long.
     * Ten seconds keeps the identity server's load bounded while making revocation feel
     * immediate. Zero disables caching entirely.
     */
    public var cacheFor: Duration = 10.seconds

    /**
     * HTTP client for the introspection calls.
     *
     * Defaults to a bundled CIO client with short timeouts. Supply your own to share a
     * connection pool or to use a specific engine.
     */
    public var httpClient: HttpClient? = null
}

/** Frozen, validated configuration. Separate from the mutable DSL so nothing changes later. */
internal class HeliumIdSettings(
    val issuer: String,
    val audience: String?,
    val providerName: String,
    val realm: String,
    val clockSkew: Duration,
    val rolesClaim: String,
    val jwksUri: String,
    val jwks: JwksConfig,
    val introspection: IntrospectionConfig,
    val introspectionBaseUrl: String,
) {

    /**
     * Builds the verification strategy.
     *
     * Offline JWKS is always constructed: introspection layers on top of it rather than
     * replacing it, so a forged token never reaches the identity server.
     */
    fun buildVerifier(): HeliumTokenVerifier {
        val offline = JwksTokenVerifier(
            issuer = issuer,
            audience = audience,
            jwksUri = jwksUri,
            cacheFor = jwks.cacheFor,
            refreshTimeout = jwks.refreshTimeout,
            rateLimitFor = jwks.rateLimitFor,
            connectTimeout = jwks.connectTimeout,
            readTimeout = jwks.readTimeout,
            jwksSizeLimit = jwks.sizeLimit,
            clockSkew = clockSkew,
            rolesClaim = rolesClaim,
        )
        if (!introspection.enabled) return offline

        val client = introspection.httpClient
            ?.let { HeliumIdClient(introspectionBaseUrl, it) }
            ?: HeliumIdClient.create(introspectionBaseUrl)

        return IntrospectionTokenVerifier(
            client = client,
            clientId = introspection.clientId,
            clientSecret = introspection.clientSecret,
            expectedIssuer = issuer,
            expectedAudience = audience,
            cacheFor = introspection.cacheFor,
            delegate = offline,
        )
    }
}

/**
 * The `heliumid` bearer authentication provider.
 *
 * Registered for you by [HeliumId]; you never construct it directly. It is public only so that
 * `authenticate("heliumid")` has a documented thing to point at.
 */
public class HeliumAuthenticationProvider internal constructor(
    config: Config,
    private val verifier: HeliumTokenVerifier,
    private val realm: String,
) : AuthenticationProvider(config) {

    /** Provider configuration. Built by [HeliumId] from [HeliumIdConfig]. */
    public class Config internal constructor(name: String?) : AuthenticationProvider.Config(name)

    override suspend fun onAuthenticate(context: AuthenticationContext) {
        val call = context.call
        val token = call.bearerToken()

        if (token == null) {
            context.reject(
                cause = AuthenticationFailedCause.NoCredentials,
                status = HttpStatusCode.Unauthorized,
                problemCode = "auth_required",
                bearerError = "invalid_request",
                detail = "Authentication is required.",
                realm = realm,
            )
            return
        }

        when (val result = verifier.verify(token, Instant.now())) {
            is VerificationResult.Valid -> context.principal(name, result.principal)

            is VerificationResult.Rejected -> context.reject(
                cause = AuthenticationFailedCause.InvalidCredentials,
                status = HttpStatusCode.Unauthorized,
                problemCode = result.problemCode,
                bearerError = result.bearerError,
                detail = result.detail,
                realm = realm,
            )

            is VerificationResult.Unavailable -> context.reject(
                // Fail closed. An identity server we cannot reach is a reason to stop serving,
                // never a reason to wave a token through.
                cause = AuthenticationFailedCause.Error(result.detail),
                status = HttpStatusCode.ServiceUnavailable,
                problemCode = "temporarily_unavailable",
                bearerError = null,
                detail = result.detail,
                realm = realm,
            )
        }
    }
}

/**
 * Extracts the bearer token.
 *
 * Only the `Bearer` scheme is accepted, and only from the `Authorization` header — never from a
 * query parameter, which would put the credential in access logs, referrers and browser
 * history.
 */
private fun ApplicationCall.bearerToken(): String? {
    val header = runCatching { request.parseAuthorizationHeader() }.getOrNull()
    val single = header as? HttpAuthHeader.Single ?: return null
    if (!single.authScheme.equals("Bearer", ignoreCase = true)) return null
    return single.blob.takeIf { it.isNotBlank() }
}

/** Registers the challenge that writes the problem+json failure response. */
private fun AuthenticationContext.reject(
    cause: AuthenticationFailedCause,
    status: HttpStatusCode,
    problemCode: String,
    bearerError: String?,
    detail: String,
    realm: String,
) {
    challenge(HELIUM_CHALLENGE_KEY, cause) { challenge, call ->
        call.respondHeliumProblem(status, problemCode, detail, bearerError, realm)
        challenge.complete()
    }
}

/**
 * Writes an RFC 9457 problem response.
 *
 * Serialized here and sent as text rather than through content negotiation: the consuming
 * application may not have `ContentNegotiation` installed at all, and an authentication failure
 * must not depend on a plugin the SDK does not control. It also guarantees the
 * `application/problem+json` content type, which negotiation would happily replace.
 */
internal suspend fun ApplicationCall.respondHeliumProblem(
    status: HttpStatusCode,
    code: String,
    detail: String,
    bearerError: String?,
    realm: String,
) {
    if (bearerError != null) {
        response.header(HttpHeaders.WWWAuthenticate, """Bearer realm="$realm", error="$bearerError"""")
    }
    val problem = ProblemDetails(
        type = "https://helium.id/errors/${code.replace('_', '-')}",
        title = code.replace('_', ' ').replaceFirstChar { it.uppercase() },
        status = status.value,
        code = code,
        detail = detail,
    )
    respondText(
        text = HeliumJson.encodeToString(ProblemDetails.serializer(), problem),
        contentType = ContentType("application", "problem+json"),
        status = status,
    )
}

private val HELIUM_CHALLENGE_KEY: Any = "HeliumIdAuth"
