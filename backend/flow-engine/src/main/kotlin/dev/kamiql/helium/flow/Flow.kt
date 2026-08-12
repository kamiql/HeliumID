package dev.kamiql.helium.flow

import dev.kamiql.helium.domain.policy.Permission

/** Stable identifier of a flow, used in audit rows, metrics and idempotency scoping. */
@JvmInline
value class FlowId(val value: String) {
    override fun toString(): String = value
}

/** Whether the engine wraps steps and commit actions in a database transaction. */
enum class TransactionPolicy {
    /** Steps, commit actions, audit rows and outbox rows all commit or all roll back. */
    Required,

    /**
     * No transaction. Only for genuinely read-only flows such as discovery or introspection.
     * A flow that writes anything must not use this.
     */
    None,
}

/** Whether a client-supplied idempotency key is honoured, demanded, or ignored. */
enum class IdempotencyPolicy {
    /** Replays the stored response when the same key and payload arrive again. */
    Optional,

    /**
     * Rejects the request when no key is supplied. Concept §2.5 lists the operations that
     * warrant this: registration, reset completion, OAuth callback processing, linking.
     */
    Required,

    None,
}

/**
 * A named, typed security flow.
 *
 * Build one with [flow]. The declaration order matters and is the execution order:
 * requirements, then steps, then commit actions, then effects.
 *
 * @param C the command type — everything the flow needs from the caller.
 * @param R what the flow produces on success.
 */
class Flow<C : Any, R : Any> internal constructor(
    val id: FlowId,
    val transactionPolicy: TransactionPolicy,
    val idempotencyPolicy: IdempotencyPolicy,
    val requirements: List<Requirement<C>>,
    val steps: List<FlowStep<C>>,
    val commitActions: List<CommitAction<C>>,
    val effects: List<DomainEffect<C>>,
    val failureHandlers: List<FailureHandler<C>>,
    val resultBuilder: (FlowState) -> R,
    /** Recorded on every audit row this flow emits. */
    val auditEventType: String,
)

/** Receiver of the flow DSL. See [flow] for an example. */
class FlowDsl<C : Any, R : Any> internal constructor(private val id: FlowId) {

    private var transactionPolicy: TransactionPolicy = TransactionPolicy.Required
    private var idempotencyPolicy: IdempotencyPolicy = IdempotencyPolicy.None
    private val requirements = mutableListOf<Requirement<C>>()
    private val steps = mutableListOf<FlowStep<C>>()
    private val commitActions = mutableListOf<CommitAction<C>>()
    private val effects = mutableListOf<DomainEffect<C>>()
    private val failureHandlers = mutableListOf<FailureHandler<C>>()
    private var resultBuilder: ((FlowState) -> R)? = null
    private var auditEventType: String = id.value

    fun transaction(policy: TransactionPolicy) {
        transactionPolicy = policy
    }

    fun idempotency(policy: IdempotencyPolicy) {
        idempotencyPolicy = policy
    }

    /** Overrides the audit `event_type`; defaults to the flow id. */
    fun auditAs(eventType: String) {
        auditEventType = eventType
    }

    fun require(requirement: Requirement<C>) {
        requirements += requirement
    }

    /** Sugar for the very common permission check. */
    fun requirePermission(permission: Permission) {
        requirements += requirement("has-permission:${permission.value}") { _, context ->
            if (context.actor.has(permission)) {
                RequirementResult.Satisfied
            } else {
                RequirementResult.Rejected(
                    dev.kamiql.helium.domain.error.AuthError.Forbidden(permission.value),
                )
            }
        }
    }

    fun step(step: FlowStep<C>) {
        steps += step
    }

    fun commitAction(action: CommitAction<C>) {
        commitActions += action
    }

    fun effect(effect: DomainEffect<C>) {
        effects += effect
    }

    fun onFailure(handler: FailureHandler<C>) {
        failureHandlers += handler
    }

    /** How to build the success value from the state the steps produced. */
    fun result(builder: (FlowState) -> R) {
        resultBuilder = builder
    }

    internal fun build(): Flow<C, R> {
        val builder = resultBuilder
            ?: error("flow '$id' does not declare result { ... }")
        require(transactionPolicy == TransactionPolicy.Required || commitActions.isEmpty()) {
            "flow '$id' declares commit actions but no transaction"
        }
        return Flow(
            id = id,
            transactionPolicy = transactionPolicy,
            idempotencyPolicy = idempotencyPolicy,
            requirements = requirements.toList(),
            steps = steps.toList(),
            commitActions = commitActions.toList(),
            effects = effects.toList(),
            failureHandlers = failureHandlers.toList(),
            resultBuilder = builder,
            auditEventType = auditEventType,
        )
    }
}

/**
 * Declares a flow.
 *
 * ```kotlin
 * val changePasswordFlow = flow<ChangePasswordCommand, Unit>(FlowId("account.change-password")) {
 *     transaction(TransactionPolicy.Required)
 *     require(Authenticated)
 *     require(ReauthenticatedWithin(Duration.ofMinutes(5)))
 *     require(EmailVerified)
 *     step(ValidateCurrentPassword(...))
 *     step(ValidateNewPasswordPolicy(...))
 *     step(HashAndStorePassword(...))
 *     commitAction(RevokeOtherSessions(...))
 *     effect(PasswordChangedNotification)
 *     result { }
 * }
 * ```
 *
 * The value of the DSL is not brevity — it is that the requirements are visible at the
 * declaration site. Concept §9.3 warns against turning this into a generic workflow engine:
 * no configuration-driven policies, no reflective step discovery, no hidden transactions.
 */
fun <C : Any, R : Any> flow(id: FlowId, block: FlowDsl<C, R>.() -> Unit): Flow<C, R> =
    FlowDsl<C, R>(id).apply(block).build()

/** Convenience for flows that produce nothing. */
fun <C : Any> unitFlow(id: FlowId, block: FlowDsl<C, Unit>.() -> Unit): Flow<C, Unit> =
    FlowDsl<C, Unit>(id).apply {
        block()
        result { }
    }.build()
