package dev.kamiql.helium.flow

import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.error.AuthErrorException
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.userIdOrNull
import dev.kamiql.helium.flow.port.AuditEntry
import dev.kamiql.helium.flow.port.AuditOutcome
import dev.kamiql.helium.flow.port.AuditPort
import dev.kamiql.helium.flow.port.MetricsPort
import dev.kamiql.helium.flow.port.OutboxContext
import dev.kamiql.helium.flow.port.OutboxPort
import dev.kamiql.helium.flow.port.TransactionManager
import org.slf4j.LoggerFactory

/**
 * Executes a [Flow].
 *
 * The order is fixed and is the security contract:
 *
 * 1. requirements, outside any transaction — a rejection must not have written anything;
 * 2. open the transaction when the flow declares one;
 * 3. steps, in declaration order, stopping at the first non-[StepResult.Continue];
 * 4. commit actions;
 * 5. outbox events and the audit row, still inside the transaction;
 * 6. commit.
 *
 * A step that fails or challenges unwinds the transaction, so a partially applied flow can
 * never be committed. External delivery of the outbox events happens later, in the `jobs`
 * worker — never here (concept §2.4).
 */
class FlowRunner(
    private val transactionManager: TransactionManager,
    private val outbox: OutboxPort,
    private val audit: AuditPort,
    private val metrics: MetricsPort = MetricsPort.NoOp,
) {

    private val log = LoggerFactory.getLogger(FlowRunner::class.java)

    suspend fun <C : Any, R : Any> execute(
        flow: Flow<C, R>,
        command: C,
        context: FlowContext,
    ): FlowResult<R> {
        val startedAt = System.nanoTime()
        return try {
            val result = runFlow(flow, command, context)
            metrics.counter(
                name = "helium_flow_executions_total",
                tags = mapOf("flow" to flow.id.value, "outcome" to result.outcomeLabel()),
            )
            result
        } catch (error: AuthErrorException) {
            // A repository or step signalled a domain failure by throwing, so the transaction
            // would roll back. Normal control flow, not a defect.
            failure(flow, command, context, error.error)
        } catch (error: Throwable) {
            // Unexpected. Log the request id, never the command: it may hold user input and,
            // in some flows, a Secret.
            log.error("flow {} failed unexpectedly (request {})", flow.id, context.requestId, error)
            metrics.counter("helium_flow_errors_total", mapOf("flow" to flow.id.value))
            failure(flow, command, context, AuthError.TemporarilyUnavailable)
        } finally {
            metrics.timer(
                name = "helium_flow_duration_nanos",
                durationNanos = System.nanoTime() - startedAt,
                tags = mapOf("flow" to flow.id.value),
            )
        }
    }

    private suspend fun <C : Any, R : Any> runFlow(
        flow: Flow<C, R>,
        command: C,
        context: FlowContext,
    ): FlowResult<R> {
        if (flow.idempotencyPolicy == IdempotencyPolicy.Required && context.idempotencyKey.isNullOrBlank()) {
            return failure(
                flow, command, context,
                AuthError.ValidationFailed(mapOf("idempotency_key" to "required")),
            )
        }

        for (requirement in flow.requirements) {
            when (val outcome = requirement.check(command, context)) {
                RequirementResult.Satisfied -> Unit

                is RequirementResult.Rejected -> {
                    log.debug("flow {} rejected by {} (request {})", flow.id, requirement.name, context.requestId)
                    return failure(flow, command, context, outcome.error)
                }

                is RequirementResult.ChallengeRequired -> {
                    recordAudit(flow, context, AuditOutcome.CHALLENGE, mapOf("requirement" to requirement.name))
                    return outcome.challenge.toResult()
                }
            }
        }

        val state = MutableFlowState()

        val body: suspend () -> FlowResult<R> = {
            runSteps(flow, command, context, state)
        }

        val outcome = try {
            when (flow.transactionPolicy) {
                TransactionPolicy.Required -> transactionManager.transaction(body)
                TransactionPolicy.None -> body()
            }
        } catch (abort: FlowAbort) {
            // Thrown from inside the transaction precisely so that it rolls back.
            @Suppress("UNCHECKED_CAST")
            abort.result as FlowResult<R>
        }

        return when (outcome) {
            is FlowResult.Failure -> failure(flow, command, context, outcome.error, outcome.redirect)
            is FlowResult.Challenge -> {
                recordAudit(flow, context, AuditOutcome.CHALLENGE, mapOf("challenge" to outcome.code))
                outcome
            }
            is FlowResult.Success -> outcome
        }
    }

    /**
     * Runs the transactional part. Failures and challenges leave via [FlowAbort] so that the
     * surrounding transaction unwinds instead of committing a half-applied flow.
     */
    private suspend fun <C : Any, R : Any> runSteps(
        flow: Flow<C, R>,
        command: C,
        context: FlowContext,
        state: MutableFlowState,
    ): FlowResult<R> {
        for (step in flow.steps) {
            when (val outcome = step.execute(command, context, state)) {
                StepResult.Continue -> Unit
                is StepResult.Fail -> throw FlowAbort(FlowResult.Failure(outcome.error))
                is StepResult.Challenge -> throw FlowAbort(outcome.challenge.toResult())
            }
        }

        for (action in flow.commitActions) {
            action.execute(command, context, state)
        }

        val events = flow.effects.flatMap { it.events(command, context, state) }
        if (events.isNotEmpty()) {
            outbox.publish(events, OutboxContext(context.requestId, context.now))
        }

        audit.record(auditEntry(flow, context, AuditOutcome.SUCCESS, state.auditMetadata(events)))

        return FlowResult.Success(flow.resultBuilder(state))
    }

    private suspend fun <C : Any, R : Any> failure(
        flow: Flow<C, R>,
        command: C,
        context: FlowContext,
        error: AuthError,
        redirect: ProtocolRedirect? = null,
    ): FlowResult<R> {
        for (handler in flow.failureHandlers) {
            runCatching { handler.onFailure(command, context, error) }
                .onFailure { log.warn("failure handler {} threw for flow {}", handler.name, flow.id, it) }
        }
        recordAudit(flow, context, AuditOutcome.FAILURE, mapOf("error" to error.code))
        return FlowResult.Failure(error, redirect)
    }

    private suspend fun recordAudit(
        flow: Flow<*, *>,
        context: FlowContext,
        outcome: AuditOutcome,
        metadata: Map<String, String>,
    ) {
        // Audit rows for failures are written outside the rolled-back transaction on purpose:
        // the whole point of a failure record is that it survives the failure.
        runCatching { audit.record(auditEntry(flow, context, outcome, metadata)) }
            .onFailure { log.error("failed to write audit row for flow {}", flow.id, it) }
    }

    private fun auditEntry(
        flow: Flow<*, *>,
        context: FlowContext,
        outcome: AuditOutcome,
        metadata: Map<String, String>,
    ): AuditEntry {
        val subject = metadata[SUBJECT_USER_ID]?.let(UserId::parse) ?: context.actor.userIdOrNull
        return AuditEntry(
            eventType = flow.auditEventType,
            outcome = outcome,
            actorUserId = context.actor.userIdOrNull,
            subjectUserId = subject,
            clientId = context.clientId,
            requestId = context.requestId,
            ipHash = context.ipAddress?.let(::hashForAudit),
            userAgentHash = context.userAgent?.let(::hashForAudit),
            occurredAt = context.now,
            metadata = metadata - SUBJECT_USER_ID,
        )
    }

    companion object {
        /**
         * State/metadata key a step sets when the audit subject differs from the actor — for
         * example an administrator suspending somebody else's account, or a login attempt
         * where there is no authenticated actor yet.
         */
        const val SUBJECT_USER_ID: String = "subject_user_id"

        /**
         * SHA-256 of an IP address or user agent.
         *
         * Lets an investigator correlate activity without the audit table itself becoming a
         * store of network identifiers (concept §3.2 stores `ip_hash`, not `ip`).
         */
        fun hashForAudit(value: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            return java.util.HexFormat.of().formatHex(digest.digest(value.toByteArray()))
        }
    }
}

/**
 * Carries a non-success outcome out of a transaction so the transaction rolls back.
 *
 * Stackless: these are frequent and the stack trace would never be read.
 */
private class FlowAbort(val result: FlowResult<Nothing>) : RuntimeException(null, null, false, false)

private fun ChallengeDescriptor.toResult(): FlowResult<Nothing> =
    FlowResult.Challenge(code, transactionId, expiresAt, methods)

private fun FlowResult<*>.outcomeLabel(): String = when (this) {
    is FlowResult.Success -> "success"
    is FlowResult.Challenge -> "challenge"
    is FlowResult.Failure -> "failure"
}

/** Non-sensitive state plus emitted event types, for the audit `metadata_json` column. */
private fun MutableFlowState.auditMetadata(events: List<DomainEvent>): Map<String, String> {
    val snapshot = diagnosticSnapshot()
    return if (events.isEmpty()) snapshot else snapshot + ("events" to events.joinToString(",") { it.type })
}
