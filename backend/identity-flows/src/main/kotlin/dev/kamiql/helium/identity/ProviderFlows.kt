package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.ExternalIdentityId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.identity.ExternalIdentity
import dev.kamiql.helium.domain.identity.ExternalProfile
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.userIdOrNull
import dev.kamiql.helium.domain.repository.ExternalIdentityRepository
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.PasswordCredentialRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.IssuedSession
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowStateKey
import dev.kamiql.helium.flow.StepResult
import dev.kamiql.helium.flow.TransactionPolicy
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimiter
import dev.kamiql.helium.flow.port.SecurityTransactionStore
import dev.kamiql.helium.flow.requirement.Authenticated
import dev.kamiql.helium.flow.requirement.RateLimited
import dev.kamiql.helium.flow.requirement.ReauthenticatedWithin
import dev.kamiql.helium.flow.step
import dev.kamiql.helium.spi.ProviderAuthorizationRequest
import dev.kamiql.helium.spi.ProviderCallbackRequest
import dev.kamiql.helium.spi.ProviderException
import dev.kamiql.helium.spi.ProviderIntent
import dev.kamiql.helium.spi.ProviderRegistry
import org.slf4j.LoggerFactory

/** Where a provider round trip should end up. */
data class BeginProviderAuthorizationCommand(
    val provider: ProviderKey,
    val redirectUri: String,
    val intent: ProviderIntent,
)

data class ProviderAuthorizationStarted(
    val authorizationUrl: String,
    /** Handle for the server-side pending state; travels in a short-lived cookie. */
    val transactionId: TransactionId,
)

data class CompleteProviderCallbackCommand(
    val provider: ProviderKey,
    val code: String,
    val state: String,
    val redirectUri: String,
    val transactionId: TransactionId,
)

sealed interface ProviderCallbackResult {
    /** The `(issuer, subject)` pair was already linked; the user is signed in. */
    data class SignedIn(val session: IssuedSession, val userId: UserId) : ProviderCallbackResult

    /** The identity was linked to the account that started the linking flow. */
    data class Linked(val provider: ProviderKey) : ProviderCallbackResult
}

/**
 * External identity provider sign-in and linking.
 *
 * The rule that shapes all of this is concept §9.4: **never link by email**. An identity is
 * matched on `(issuer, subject)` and nothing else, and an unrecognised identity results in
 * `provider_link_required` rather than a silently created or silently merged account.
 *
 * That is deliberately less convenient than "sign in with Google creates your account". It is
 * also the difference between an attacker who controls an unverified email claim getting into
 * an existing account and not.
 */
class ProviderFlows(
    private val users: UserRepository,
    private val identities: ExternalIdentityRepository,
    private val credentials: PasswordCredentialRepository,
    private val mfaRepository: MfaRepository,
    private val sessions: SessionRepository,
    private val providers: ProviderRegistry,
    private val sessionService: SessionService,
    private val transactions: SecurityTransactionStore,
    private val rateLimiter: RateLimiter,
    private val random: RandomSource,
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
) {

    private val log = LoggerFactory.getLogger(ProviderFlows::class.java)

    private val startedKey = FlowStateKey<ProviderAuthorizationStarted>("provider_authorization")
    private val resultKey = FlowStateKey<ProviderCallbackResult>("provider_result", sensitive = true)
    private val eventKey = FlowStateKey<DomainEvent>("provider_event")

    /**
     * Builds the outbound authorization URL and stashes the pending state server side.
     *
     * The `state`, `nonce` and PKCE verifier never touch the browser: it receives only an
     * opaque transaction handle. A client-held state would have to be integrity protected, and
     * getting that wrong is exactly how CSRF sneaks back in.
     */
    val beginAuthorization: Flow<BeginProviderAuthorizationCommand, ProviderAuthorizationStarted> =
        flow(FlowId("provider.authorize.begin")) {
            transaction(TransactionPolicy.None)

            step(
                step("build-url") { command, context, state ->
                    if (command.intent == ProviderIntent.LINK && context.actor.userIdOrNull == null) {
                        return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    }
                    val provider = providers[command.provider]
                        ?: return@step StepResult.Fail(AuthError.NotFound)

                    val redirect = try {
                        provider.createAuthorizationRequest(
                            ProviderAuthorizationRequest(
                                redirectUri = command.redirectUri,
                                intent = command.intent,
                            ),
                        )
                    } catch (error: ProviderException) {
                        log.warn("provider {} failed to build an authorization request", command.provider, error)
                        return@step StepResult.Fail(AuthError.ProviderUnavailable)
                    }

                    val transactionId = TransactionId(random.token(24))
                    transactions.put(
                        id = transactionId,
                        kind = PROVIDER_TRANSACTION_KIND,
                        // The initiating user is bound into the transaction, so a callback
                        // cannot be replayed into a different account's linking flow.
                        payload = buildString {
                            append(command.intent.name).append(FIELD_SEPARATOR)
                            append(context.actor.userIdOrNull?.value?.toString().orEmpty()).append(FIELD_SEPARATOR)
                            append(redirect.pendingState)
                        },
                        ttl = lifetimes.providerLinkTransaction,
                    )

                    state[startedKey] = ProviderAuthorizationStarted(redirect.authorizationUrl, transactionId)
                    StepResult.Continue
                },
            )

            result { state -> state.require(startedKey) }
        }

    /**
     * Handles the provider callback.
     *
     * Sign-in path: the `(issuer, subject)` must already be linked. Link path: the identity is
     * attached to the account that started the flow, and only if it is not attached elsewhere.
     */
    val completeCallback: Flow<CompleteProviderCallbackCommand, ProviderCallbackResult> =
        flow(FlowId("provider.authorize.callback")) {
            transaction(TransactionPolicy.Required)
            auditAs("provider.callback")

            require(
                RateLimited<CompleteProviderCallbackCommand>(
                    "provider.callback", RateLimit.OAUTH_CALLBACK_FAILURES, rateLimiter,
                ) { command, context -> "${command.provider.value}|${context.ipAddress.orEmpty()}" },
            )

            step(
                step("exchange-and-resolve") { command, context, state ->
                    val provider = providers[command.provider]
                        ?: return@step StepResult.Fail(AuthError.NotFound)

                    // Atomic take: the callback is single use even under a replay race.
                    val stored = transactions.take(command.transactionId, PROVIDER_TRANSACTION_KIND)
                        ?: return@step StepResult.Fail(AuthError.OAuthStateInvalid)

                    val parts = stored.split(FIELD_SEPARATOR, limit = 3)
                    if (parts.size != 3) return@step StepResult.Fail(AuthError.OAuthStateInvalid)
                    val intent = runCatching { ProviderIntent.valueOf(parts[0]) }.getOrNull()
                        ?: return@step StepResult.Fail(AuthError.OAuthStateInvalid)
                    val initiatingUserId = parts[1].takeIf { it.isNotBlank() }?.let(UserId::parse)

                    val profile = try {
                        provider.exchangeCode(
                            ProviderCallbackRequest(
                                code = command.code,
                                state = command.state,
                                redirectUri = command.redirectUri,
                                pendingState = parts[2],
                            ),
                        )
                    } catch (error: ProviderException) {
                        log.warn("provider {} callback failed: {}", command.provider, error.message)
                        return@step StepResult.Fail(
                            if (error.retryable) AuthError.ProviderUnavailable
                            else AuthError.ProviderInvalidResponse,
                        )
                    }

                    // The adapter's issuer is configuration; a profile claiming a different one
                    // means the adapter is misbehaving and must not be trusted.
                    if (profile.issuer != provider.issuer) {
                        log.error("provider {} returned a profile for issuer {}", provider.key, profile.issuer)
                        return@step StepResult.Fail(AuthError.ProviderInvalidResponse)
                    }

                    when (intent) {
                        ProviderIntent.SIGN_IN -> signIn(profile, context, state)
                        ProviderIntent.LINK -> link(profile, initiatingUserId, context, state)
                    }
                },
            )

            effect(
                effect("provider-events") { _, _, state ->
                    listOfNotNull(state[eventKey])
                },
            )

            result { state -> state.require(resultKey) }
        }

    private suspend fun signIn(
        profile: ExternalProfile,
        context: dev.kamiql.helium.flow.FlowContext,
        state: dev.kamiql.helium.flow.MutableFlowState,
    ): StepResult {
        val identity = identities.findByIssuerAndSubject(profile.issuer, profile.subject)
            // Not linked. We deliberately do *not* look the email up and offer to merge:
            // provider emails may be unverified or reassigned (concept §9.4). The user must
            // sign in with an existing credential and link deliberately.
            ?: return StepResult.Fail(AuthError.ProviderLinkRequired)

        val user = users.findById(identity.userId)
            ?: return StepResult.Fail(AuthError.InvalidCredentials)
        user.toAccessError()?.let { return StepResult.Fail(it) }

        identities.touchLogin(identity.id, context.now)

        val issued = sessionService.issue(
            userId = user.id,
            clientId = context.clientId,
            methods = setOf(AuthenticationMethod.EXTERNAL_PROVIDER),
            context = context,
        )
        state[resultKey] = ProviderCallbackResult.SignedIn(issued, user.id)
        state[eventKey] = DomainEvent.LoginSucceeded(
            userId = user.id,
            sessionId = issued.session.id,
            clientId = issued.session.clientId,
            newDevice = sessionService.isNewDevice(user.id, context, context.now),
        )
        return StepResult.Continue
    }

    private suspend fun link(
        profile: ExternalProfile,
        initiatingUserId: UserId?,
        context: dev.kamiql.helium.flow.FlowContext,
        state: dev.kamiql.helium.flow.MutableFlowState,
    ): StepResult {
        val userId = initiatingUserId ?: return StepResult.Fail(AuthError.AuthenticationRequired)
        // The session that finishes the link must be the session that started it.
        if (context.actor.userIdOrNull != userId) return StepResult.Fail(AuthError.Forbidden())

        val existing = identities.findByIssuerAndSubject(profile.issuer, profile.subject)
        if (existing != null) {
            return if (existing.userId == userId) StepResult.Fail(AuthError.ProviderAlreadyLinked)
            // Never move an identity between accounts, and never say whose it is.
            else StepResult.Fail(AuthError.IdentityAlreadyLinked)
        }
        if (identities.findByUserAndProvider(userId, profile.providerKey) != null) {
            return StepResult.Fail(AuthError.ProviderAlreadyLinked)
        }

        identities.link(
            ExternalIdentity(
                id = ExternalIdentityId.random(),
                userId = userId,
                providerKey = profile.providerKey,
                issuer = profile.issuer,
                subject = profile.subject,
                providerEmail = profile.email,
                createdAt = context.now,
                lastLoginAt = null,
            ),
        )

        state[resultKey] = ProviderCallbackResult.Linked(profile.providerKey)
        state[eventKey] = DomainEvent.ProviderLinked(userId, profile.providerKey)
        return StepResult.Continue
    }

    /**
     * Unlinks a provider.
     *
     * Refuses when it would leave the account with no way in — concept §2.6 lists the
     * acceptable remaining credentials: a local password, another external identity, a passkey,
     * or a recovery path.
     */
    val unlinkProvider: Flow<UnlinkProviderCommand, Unit> =
        flow(FlowId("account.provider.unlink")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_PROVIDER_MANAGE)

            step(
                step("unlink") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    identities.findByUserAndProvider(userId, command.provider)
                        ?: return@step StepResult.Fail(AuthError.NotFound)

                    val hasPassword = credentials.findByUserId(userId) != null
                    val otherIdentities = identities.findByUserId(userId)
                        .count { it.providerKey != command.provider }
                    val hasRecovery = mfaRepository.countUnusedRecoveryCodes(userId) > 0

                    if (!hasPassword && otherIdentities == 0 && !hasRecovery) {
                        return@step StepResult.Fail(AuthError.LastCredentialRemoval)
                    }

                    identities.unlink(userId, command.provider)
                    state[unlinkedUserKey] = userId
                    StepResult.Continue
                },
            )

            effect(
                effect("provider-unlinked") { command, _, state ->
                    listOf(DomainEvent.ProviderUnlinked(state.require(unlinkedUserKey), command.provider))
                },
            )

            result { }
        }

    private val unlinkedUserKey = FlowStateKey<UserId>("unlinked_user")

    companion object {
        /** Kind used for provider handles in the security transaction store. */
        const val PROVIDER_TRANSACTION_KIND: String = "provider-auth"

        /**
         * Unit separator (U+001F) between the fields of the stored pending state.
         *
         * Cannot occur in an intent name, a UUID or the adapter's JSON state, so the split is
         * unambiguous without needing an escaping scheme.
         */
        private const val FIELD_SEPARATOR: Char = ''
    }
}
