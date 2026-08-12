package dev.kamiql.helium.flow.requirement

import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.Requirement
import dev.kamiql.helium.flow.RequirementResult
import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimitDecision
import dev.kamiql.helium.flow.port.RateLimitKey
import dev.kamiql.helium.flow.port.RateLimiter
import java.time.Duration

/**
 * The reusable requirements from concept §2.2.
 *
 * Each is a small object so that a flow definition reads as a list of policy statements. New
 * requirements belong here only when they are genuinely reusable; a one-off check should be a
 * lambda at the flow definition site, where it stays visible.
 */

/** The caller presented some form of credential. */
object Authenticated : Requirement<Any> {
    override val name = "authenticated"

    override suspend fun check(command: Any, context: FlowContext): RequirementResult =
        when (context.actor) {
            is Principal.Anonymous -> RequirementResult.Rejected(AuthError.AuthenticationRequired)
            else -> RequirementResult.Satisfied
        }
}

/** The caller is a human, not a `client_credentials` machine principal. */
object AuthenticatedUser : Requirement<Any> {
    override val name = "authenticated-user"

    override suspend fun check(command: Any, context: FlowContext): RequirementResult =
        when (context.actor) {
            is Principal.UserSession, is Principal.TokenBearer -> RequirementResult.Satisfied
            is Principal.ServiceClient -> RequirementResult.Rejected(AuthError.Forbidden())
            Principal.Anonymous -> RequirementResult.Rejected(AuthError.AuthenticationRequired)
        }
}

/** Nobody may be signed in. Guards registration and password-reset request. */
object Unauthenticated : Requirement<Any> {
    override val name = "unauthenticated"

    override suspend fun check(command: Any, context: FlowContext): RequirementResult =
        when (context.actor) {
            Principal.Anonymous -> RequirementResult.Satisfied
            else -> RequirementResult.Rejected(AuthError.Conflict)
        }
}

/**
 * The user proved their identity within [window].
 *
 * Compares against `Session.authenticatedAt`, not `createdAt`: a long-lived session must not
 * inherit the freshness of the moment it was created. Concept §4.10 requires this for every
 * account-takeover-sensitive operation.
 *
 * A bearer-token principal cannot satisfy this — there is no interactive session to re-prove
 * against — so such callers are told to reauthenticate rather than silently allowed.
 */
class ReauthenticatedWithin(
    private val window: Duration,
    private val sessions: SessionRepository,
) : Requirement<Any> {

    override val name = "reauthenticated-within-${window.toMinutes()}m"

    override suspend fun check(command: Any, context: FlowContext): RequirementResult {
        val actor = context.actor
        if (actor !is Principal.UserSession) {
            return RequirementResult.Rejected(
                if (actor is Principal.Anonymous) AuthError.AuthenticationRequired
                else AuthError.ReauthenticationRequired,
            )
        }
        val session = sessions.findById(actor.sessionId)
            ?: return RequirementResult.Rejected(AuthError.AuthenticationRequired)

        return if (session.reauthenticatedWithin(context.now, window)) {
            RequirementResult.Satisfied
        } else {
            RequirementResult.Rejected(AuthError.ReauthenticationRequired)
        }
    }
}

/**
 * The account's primary email address is verified.
 *
 * Deliberately not applied to login itself: a user with an unverified address must still be
 * able to sign in far enough to trigger a resend.
 */
class EmailVerified(private val users: UserRepository) : Requirement<Any> {

    override val name = "email-verified"

    override suspend fun check(command: Any, context: FlowContext): RequirementResult {
        val userId = when (val actor = context.actor) {
            is Principal.UserSession -> {
                // The session principal already carries the flag, so the common path costs no query.
                return if (actor.emailVerified) RequirementResult.Satisfied
                else RequirementResult.Rejected(AuthError.EmailUnverified)
            }
            is Principal.TokenBearer -> actor.userId
            else -> return RequirementResult.Rejected(AuthError.AuthenticationRequired)
        }
        val user = users.findById(userId) ?: return RequirementResult.Rejected(AuthError.AuthenticationRequired)
        return if (user.isEmailVerified) RequirementResult.Satisfied
        else RequirementResult.Rejected(AuthError.EmailUnverified)
    }
}

/**
 * A second factor was actually used for this session — not merely enrolled.
 *
 * Enrollment says what the user *can* do; `amr` says what they *did*. Only the latter is
 * evidence.
 */
object MfaSatisfied : Requirement<Any> {
    override val name = "mfa-satisfied"

    override suspend fun check(command: Any, context: FlowContext): RequirementResult {
        val methods = when (val actor = context.actor) {
            is Principal.UserSession -> actor.authenticationMethods
            is Principal.TokenBearer -> actor.authenticationMethods
            else -> return RequirementResult.Rejected(AuthError.AuthenticationRequired)
        }
        return if (methods.any { it.isSecondFactor }) {
            RequirementResult.Satisfied
        } else {
            RequirementResult.Rejected(AuthError.ReauthenticationRequired)
        }
    }
}

/** The principal holds [permission]. */
class HasPermission(private val permission: Permission) : Requirement<Any> {
    override val name = "permission:${permission.value}"

    override suspend fun check(command: Any, context: FlowContext): RequirementResult =
        if (context.actor.has(permission)) {
            RequirementResult.Satisfied
        } else if (context.actor is Principal.Anonymous) {
            RequirementResult.Rejected(AuthError.AuthenticationRequired)
        } else {
            RequirementResult.Rejected(AuthError.Forbidden(permission.value))
        }
}

/**
 * Consumes a rate-limit permit before the flow does any expensive work.
 *
 * Concept §2.6: "Rate-limit before expensive password verification." Placing this as a
 * requirement rather than a step guarantees it runs before the transaction opens and before
 * any Argon2 verification burns 64 MiB.
 *
 * @param keyOf derives the discriminator from the command. It must return an already
 *        normalized value, and a hashed one where the input is personal data.
 */
class RateLimited<C : Any>(
    private val dimension: String,
    private val limit: RateLimit,
    private val limiter: RateLimiter,
    private val keyOf: (C, FlowContext) -> String?,
) : Requirement<C> {

    override val name = "rate-limit:$dimension"

    override suspend fun check(command: C, context: FlowContext): RequirementResult {
        val value = keyOf(command, context) ?: return RequirementResult.Satisfied
        return when (val decision = limiter.consume(RateLimitKey(dimension, value), limit)) {
            is RateLimitDecision.Allowed -> RequirementResult.Satisfied
            is RateLimitDecision.Limited -> RequirementResult.Rejected(AuthError.RateLimited(decision.retryAfter))
        }
    }
}
