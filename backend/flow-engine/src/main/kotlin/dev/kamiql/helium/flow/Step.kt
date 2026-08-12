package dev.kamiql.helium.flow

import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent

/**
 * One deterministic unit of work inside a flow.
 *
 * Steps run **inside** the transaction (when the flow declares one) and may read and write
 * through repositories. They must not perform network I/O: concept §2.4 forbids sending mail
 * or calling a provider inside the transaction that updates the user.
 */
interface FlowStep<in C> {

    val name: String

    suspend fun execute(command: C, context: FlowContext, state: MutableFlowState): StepResult
}

/**
 * A step's outcome.
 *
 * [Challenge] exists so a step that discovers mid-flow that MFA is needed — which it can only
 * know after loading the account — can hand control back without throwing.
 */
sealed interface StepResult {
    data object Continue : StepResult
    data class Fail(val error: AuthError) : StepResult
    data class Challenge(val challenge: ChallengeDescriptor) : StepResult
}

/**
 * Work that runs inside the transaction after every step succeeded.
 *
 * Reserved for consequences rather than the operation itself — revoking other sessions after
 * a password change, for example. Committed atomically with the change that triggered it, so
 * there is no window in which the password is new but old sessions are still valid.
 */
interface CommitAction<in C> {
    val name: String
    suspend fun execute(command: C, context: FlowContext, state: FlowState)
}

/**
 * An external consequence: mail, webhook, push, analytics, cache invalidation.
 *
 * Effects do **not** perform the work. They return domain events which the engine writes to
 * the transactional outbox inside the same transaction; the `jobs` worker delivers them after
 * commit. That is the whole point of the outbox — CLAUDE.md: "Email, webhook, and notification
 * work must be transactional outbox effects, never inline database-transaction side effects."
 */
interface DomainEffect<in C> {
    val name: String
    suspend fun events(command: C, context: FlowContext, state: FlowState): List<DomainEvent>
}

/** Runs when the flow fails, inside no transaction. Used to record failure audit events. */
interface FailureHandler<in C> {
    val name: String
    suspend fun onFailure(command: C, context: FlowContext, error: AuthError)
}

// --- lambda builders ---------------------------------------------------------

fun <C> step(name: String, execute: suspend (C, FlowContext, MutableFlowState) -> StepResult): FlowStep<C> =
    object : FlowStep<C> {
        override val name: String = name
        override suspend fun execute(command: C, context: FlowContext, state: MutableFlowState): StepResult =
            execute(command, context, state)
    }

fun <C> commitAction(name: String, execute: suspend (C, FlowContext, FlowState) -> Unit): CommitAction<C> =
    object : CommitAction<C> {
        override val name: String = name
        override suspend fun execute(command: C, context: FlowContext, state: FlowState) =
            execute(command, context, state)
    }

fun <C> effect(name: String, events: suspend (C, FlowContext, FlowState) -> List<DomainEvent>): DomainEffect<C> =
    object : DomainEffect<C> {
        override val name: String = name
        override suspend fun events(command: C, context: FlowContext, state: FlowState): List<DomainEvent> =
            events(command, context, state)
    }
