package dev.kamiql.helium.api

import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.crypto.HeliumClock
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.repository.AuthorizationCodeRepository
import dev.kamiql.helium.domain.repository.ClientRepository
import dev.kamiql.helium.domain.repository.ConsentRepository
import dev.kamiql.helium.domain.repository.ExternalIdentityRepository
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.RoleRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.FlowResult
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.identity.AdminFlows
import dev.kamiql.helium.identity.AuthorizedAppFlows
import dev.kamiql.helium.identity.AuthorizedAppService
import dev.kamiql.helium.identity.IdentityFlows
import dev.kamiql.helium.identity.MfaFlows
import dev.kamiql.helium.identity.PasswordPolicyService
import dev.kamiql.helium.identity.ProviderFlows
import dev.kamiql.helium.identity.TrustedDeviceService
import dev.kamiql.helium.oauth.ClientAdminFlows
import dev.kamiql.helium.oauth.OAuthFlows
import dev.kamiql.helium.oauth.SigningKeyService
import dev.kamiql.helium.oauth.TokenIssuer
import dev.kamiql.helium.spi.ProviderRegistry
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.route
import io.ktor.server.routing.routing

/**
 * Everything the HTTP layer needs, gathered once.
 *
 * A single bundle rather than fifteen constructor parameters on each route file: the wiring
 * lives in `app`, and the routes stay readable.
 */
class HeliumApiDependencies(
    val config: HttpSecurityConfig,
    val clock: HeliumClock,
    val random: RandomSource,
    val flowRunner: FlowRunner,
    val principals: PrincipalResolver,

    val identityFlows: IdentityFlows,
    val mfaFlows: MfaFlows,
    val adminFlows: AdminFlows,
    val providerFlows: ProviderFlows,
    val oauthFlows: OAuthFlows,
    val clientAdminFlows: ClientAdminFlows,

    val users: UserRepository,
    val sessions: SessionRepository,
    val roles: RoleRepository,
    val clients: ClientRepository,
    val consents: ConsentRepository,
    val identities: ExternalIdentityRepository,
    val mfaRepository: MfaRepository,
    val authorizationCodes: AuthorizationCodeRepository,

    /**
     * Read and revoke side of trusted devices.
     *
     * A service rather than a flow because listing and forgetting a device carry no requirements
     * beyond "you are signed in and it is yours", and the second half is enforced by the query
     * itself. The issuing side stays inside the login and MFA flows, where the assurance decision
     * belongs.
     */
    val trustedDevices: TrustedDeviceService,

    /**
     * Read side of "which applications hold access to my account".
     *
     * Split the same way trusted devices are: the listing needs no requirement beyond a signed-in
     * caller and is scoped by the query itself, while the revocation changes a security posture
     * and therefore runs as a flow that leaves an audit row.
     */
    val authorizedApps: AuthorizedAppService,
    val authorizedAppFlows: AuthorizedAppFlows,

    val tokenIssuer: TokenIssuer,
    val signingKeys: SigningKeyService,
    val passwordPolicy: PasswordPolicyService,
    val providers: ProviderRegistry,
    val auditQuery: AuditQueryPort,
)

/**
 * The scrape side of the metrics registry.
 *
 * Declared here for the same reason as [AuditQueryPort]: the endpoint is an HTTP concern and
 * belongs to this module, while *which* registry backs it is an infrastructure choice the
 * composition root makes. Keeping it a one-method port means `api-http` never sees Micrometer.
 */
interface MetricsEndpoint {
    /** The registry's current state, already in the exposition format [contentType] names. */
    fun scrape(): String

    /** Prometheus text exposition by default; a different registry may answer otherwise. */
    val contentType: String get() = "text/plain; version=0.0.4; charset=utf-8"
}

/**
 * Read side of the audit log, declared here so `api-http` does not depend on the persistence
 * module directly.
 */
interface AuditQueryPort {
    suspend fun query(
        subjectUserId: dev.kamiql.helium.domain.common.UserId?,
        eventType: String?,
        limit: Int,
        offset: Long,
    ): dev.kamiql.helium.domain.repository.Page<AuditRecordResponse>
}

/**
 * Installs the whole HTTP surface: plugins, health probes and every route.
 *
 * One assembly point, called both by the composition root in `app` and by the route-inventory
 * test. That is the point of it being here rather than in `app`: a test that assembled the
 * application itself would be certifying a tree that only the test serves, and the two would
 * drift apart exactly when a route was added — which is the drift the inventory exists to catch.
 *
 * @param readiness backs `/health/ready`; the composition root passes a cheap database probe.
 * @param metrics backs `/metrics`. Always served on the application port — restricting who may
 *        reach it is the edge's job, and both Caddyfiles do exactly that (concept §7.5: scrape
 *        counters leak login volumes, failure rates and client identifiers).
 */
fun Application.installHeliumApi(
    security: HttpSecurityConfig,
    dependencies: HeliumApiDependencies,
    metrics: MetricsEndpoint,
    readiness: suspend () -> Boolean,
) {
    installHeliumPlugins(security)
    installHealthRoutes(readiness)
    installMetricsRoute(metrics)
    routing { heliumRoutes(dependencies) }
}

/**
 * Installs every HeliumID route.
 *
 * The layout matches concept §5.1 and §5.2: protocol endpoints at the root where the
 * specifications expect them, everything else under `/v1`.
 */
fun Route.heliumRoutes(dependencies: HeliumApiDependencies) {
    discoveryRoutes(dependencies)
    oauthRoutes(dependencies)
    userInfoRoute(dependencies)

    route("/v1") {
        authRoutes(dependencies)
        accountRoutes(dependencies)
        adminRoutes(dependencies)
    }
}

// --- shared route helpers -------------------------------------------------------

/**
 * Resolves the caller and builds the flow context.
 *
 * Every handler starts here, so authentication happens exactly once per request and the
 * resulting [Principal] is passed explicitly rather than looked up again deeper in the stack.
 */
suspend fun ApplicationCall.heliumContext(
    dependencies: HeliumApiDependencies,
    clientId: dev.kamiql.helium.domain.common.ClientId? = null,
): Pair<Principal, FlowContext> {
    val now = dependencies.clock.now()
    val actor = dependencies.principals.resolve(this, now)
    return actor to toFlowContext(actor, now, dependencies.config, clientId)
}

/**
 * Enforces CSRF on cookie-authenticated state changes and responds if it fails.
 *
 * @return `true` when the caller may proceed.
 */
suspend fun ApplicationCall.enforceCsrf(dependencies: HeliumApiDependencies): Boolean {
    val error = checkCsrf(dependencies.config) ?: return true
    respondProblem(error)
    return false
}

/**
 * Renders a [FlowResult].
 *
 * A `Challenge` becomes an `mfa_required` problem carrying the transaction handle and the
 * available methods, which is exactly the payload concept §5.3 specifies — the client can open
 * the right UI without a second round trip.
 */
suspend inline fun <R : Any> ApplicationCall.respondFlow(
    result: FlowResult<R>,
    onSuccess: (R) -> Unit,
) {
    when (result) {
        is FlowResult.Success -> onSuccess(result.value)
        is FlowResult.Failure -> respondProblem(result.error)
        is FlowResult.Challenge -> respondProblem(
            AuthError.MfaRequired(
                transactionId = TransactionId(result.transactionId.value),
                methods = result.methods,
                expiresAt = result.expiresAt,
            ),
        )
    }
}

/** Responds `204 No Content` on success. */
suspend fun ApplicationCall.respondFlowNoContent(result: FlowResult<*>) {
    when (result) {
        is FlowResult.Success -> respond(HttpStatusCode.NoContent)
        is FlowResult.Failure -> respondProblem(result.error)
        is FlowResult.Challenge -> respondProblem(
            AuthError.MfaRequired(result.transactionId, result.methods, result.expiresAt),
        )
    }
}
