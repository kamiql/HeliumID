package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.userIdOrNull
import dev.kamiql.helium.domain.repository.ClientRepository
import dev.kamiql.helium.domain.repository.ConsentRepository
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowStateKey
import dev.kamiql.helium.flow.StepResult
import dev.kamiql.helium.flow.TransactionPolicy
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.requirement.Authenticated
import dev.kamiql.helium.flow.step
import java.time.Instant

/**
 * One scope as the account owner should read it.
 *
 * Carries the catalogue description rather than the bare name, because "what did I agree to" is
 * only answerable in prose. Declared here instead of reusing the consent screen's type: this
 * module deliberately does not depend on `protocol-oauth2-oidc`.
 */
data class AuthorizedScope(val name: String, val description: String)

/**
 * An application that currently has access to the account.
 *
 * Assembled from two independent sources, which is the whole point of the type. A stored consent
 * says the user agreed; a live refresh-token family says the client can still act. Neither alone
 * answers "what is connected to my account": first-party clients registered with `skipConsent`
 * never produce a consent row, and a consent whose tokens have all expired grants nothing today
 * but will be honoured silently the next time that client asks.
 */
data class AuthorizedApp(
    val clientId: ClientId,
    /** Registered display name, so the list is readable without knowing client ids. */
    val name: String,
    /** Union of the consented scopes and those carried by live token families. */
    val scopes: List<AuthorizedScope>,
    /** When access began: the earliest of the consent and the oldest live family. */
    val authorizedAt: Instant,
    /** Newest live family, or `null` when the client holds no usable tokens right now. */
    val lastAuthorizedAt: Instant?,
    val activeGrants: Int,
    /**
     * Whether a consent record backs this entry.
     *
     * `false` marks a first-party client that skipped the consent screen. Shown rather than
     * hidden: it has access either way, and the owner is entitled to know it is there.
     */
    val consented: Boolean,
)

/**
 * Read side of "which applications can reach my account".
 *
 * A service rather than a flow, for the same reason [TrustedDeviceService] is one: listing your
 * own grants carries no requirement beyond "you are signed in", and every query below is keyed
 * on the caller's own [UserId], so ownership is enforced by the lookup instead of by a check
 * that could be forgotten.
 */
class AuthorizedAppService(
    private val consents: ConsentRepository,
    private val refreshTokens: RefreshTokenRepository,
    private val clients: ClientRepository,
) {

    /**
     * Every application with a standing consent or a live token family, newest activity first.
     *
     * Clients are resolved one at a time. A user has a handful of connected applications, not
     * thousands, and inventing a bulk port for that would buy nothing; the scope catalogue *is*
     * fetched once, because it is the same list for every row.
     */
    suspend fun list(userId: UserId, now: Instant): List<AuthorizedApp> {
        val consented = consents.listForUser(userId).associateBy { it.clientId }
        val families = refreshTokens.listActiveFamiliesForUser(userId, now).groupBy { it.clientId }
        val clientIds = consented.keys + families.keys
        if (clientIds.isEmpty()) return emptyList()

        val catalogue = clients.listScopes().associateBy { it.name }

        return clientIds.mapNotNull { clientId ->
            // A deleted client cascades its consents and token families away, so this is a
            // belt-and-braces guard against a row that outlived its registration rather than a
            // case that should occur.
            val client = clients.findById(clientId) ?: return@mapNotNull null
            val consent = consented[clientId]
            val live = families[clientId].orEmpty()

            val grantedScopes = consent?.grantedScopes.orEmpty() + live.flatMap { it.scopes }
            val startedAt = listOfNotNull(consent?.grantedAt, live.minOfOrNull { it.createdAt }).min()

            AuthorizedApp(
                clientId = clientId,
                name = client.name,
                scopes = grantedScopes.toAuthorizedScopes(catalogue),
                authorizedAt = startedAt,
                lastAuthorizedAt = live.maxOfOrNull { it.createdAt },
                activeGrants = live.size,
                consented = consent != null,
            )
        }.sortedWith(
            compareByDescending<AuthorizedApp> { it.lastAuthorizedAt ?: Instant.MIN }
                .thenByDescending { it.authorizedAt },
        )
    }

    /**
     * Renders scope names for display.
     *
     * Implicit scopes are dropped exactly as the consent screen drops them: `openid` is a
     * protocol switch the user was never asked about, and listing it here would imply they
     * approved something they did not see.
     */
    private fun Set<String>.toAuthorizedScopes(catalogue: Map<String, Scope>): List<AuthorizedScope> =
        filterNot { catalogue[it]?.implicit == true }
            .sorted()
            .map { AuthorizedScope(it, catalogue[it]?.description ?: it) }
}

/**
 * Write side: cutting an application off.
 *
 * A flow rather than another service method, on the same grounds as
 * [IdentityFlows.revokeTrustedDevice] — it changes a security posture and therefore owes the
 * audit log a row.
 */
class AuthorizedAppFlows(
    private val consents: ConsentRepository,
    private val refreshTokens: RefreshTokenRepository,
) {

    private val userIdKey = FlowStateKey<UserId>("user")
    private val revokedGrantsKey = FlowStateKey<Int>("revoked_grants")

    /**
     * Revokes the caller's own authorization of one client.
     *
     * Both halves matter and neither implies the other. Dropping the consent alone would leave
     * the client's refresh tokens minting access tokens until they expired; killing the tokens
     * alone would let the next authorization request sail through the consent screen on the
     * strength of the standing approval.
     *
     * Already-issued access tokens are not invalidated — they are short-lived JWTs and no `jti`
     * is recorded per issue, so there is nothing to revoke them by. Documented in the threat
     * model rather than papered over.
     *
     * Nothing revoked means [AuthError.NotFound], which is also the answer for an unknown client
     * and for somebody else's grant. Distinguishing them would turn this endpoint into an oracle
     * for which client ids exist.
     */
    val revokeAuthorization: Flow<RevokeAuthorizationCommand, Unit> =
        flow(FlowId("account.authorization.revoke")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            requirePermission(Permission.ACCOUNT_SESSION_MANAGE)
            auditAs("account.authorization.revoke")

            step(
                step("revoke") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    // Both calls are scoped to the caller's own id: that is the ownership check.
                    val consentRevoked = consents.revoke(userId, command.clientId, context.now)
                    val grantsRevoked = refreshTokens.revokeFamiliesForUserAndClient(
                        userId = userId,
                        clientId = command.clientId,
                        at = context.now,
                    )
                    if (!consentRevoked && grantsRevoked == 0) {
                        return@step StepResult.Fail(AuthError.NotFound)
                    }

                    state[userIdKey] = userId
                    state[revokedGrantsKey] = grantsRevoked
                    StepResult.Continue
                },
            )

            effect(
                effect("authorization-revoked") { command, _, state ->
                    listOf(
                        DomainEvent.AuthorizationRevoked(
                            userId = state.require(userIdKey),
                            clientId = command.clientId,
                            revokedGrants = state.require(revokedGrantsKey),
                        ),
                    )
                },
            )

            result { }
        }
}
