package dev.kamiql.helium.flow

import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.error.AuthError
import java.time.Instant

/**
 * A precondition that must hold before a flow may change anything.
 *
 * Requirements are declared in the flow definition, which means the security policy of an
 * operation is readable in one place without following call chains into route handlers.
 * CLAUDE.md: "Every state-changing flow declares authentication, reauthentication, MFA,
 * email-verification, authorization, and idempotency requirements explicitly."
 *
 * Requirements run **before** the transaction opens and must not mutate anything.
 */
interface Requirement<in C> {

    /** Stable name for audit records and metrics. */
    val name: String

    suspend fun check(command: C, context: FlowContext): RequirementResult
}

/**
 * Three outcomes, not a boolean.
 *
 * Concept §2.2: "Requirements should produce explicit outcomes, not plain Boolean values." A
 * boolean cannot distinguish "you may not" from "not yet, prove something else first", and
 * collapsing the two is how MFA prompts turn into 403s.
 */
sealed interface RequirementResult {

    data object Satisfied : RequirementResult

    data class Rejected(val error: AuthError) : RequirementResult

    data class ChallengeRequired(val challenge: ChallengeDescriptor) : RequirementResult
}

/**
 * Describes a challenge the caller must complete.
 *
 * @param transactionId handle for the server-side transaction that holds the pending outcome.
 * @param methods which challenge types are acceptable, e.g. `totp`, `recovery_code`.
 */
data class ChallengeDescriptor(
    val code: String,
    val transactionId: TransactionId,
    val expiresAt: Instant,
    val methods: Set<String> = emptySet(),
) {
    companion object {
        const val MFA_REQUIRED: String = "mfa_required"
        const val CONSENT_REQUIRED: String = "consent_required"
        const val REAUTHENTICATION_REQUIRED: String = "reauthentication_required"
    }
}

/** Builds a [Requirement] from a lambda, for one-off checks that need no class. */
fun <C> requirement(
    name: String,
    check: suspend (C, FlowContext) -> RequirementResult,
): Requirement<C> = object : Requirement<C> {
    override val name: String = name
    override suspend fun check(command: C, context: FlowContext): RequirementResult = check(command, context)
}
