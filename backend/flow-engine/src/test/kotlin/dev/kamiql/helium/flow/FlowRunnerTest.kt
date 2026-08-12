package dev.kamiql.helium.flow

import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.error.AuthErrorException
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.flow.port.AuditEntry
import dev.kamiql.helium.flow.port.AuditOutcome
import dev.kamiql.helium.flow.port.AuditPort
import dev.kamiql.helium.flow.port.OutboxContext
import dev.kamiql.helium.flow.port.OutboxPort
import dev.kamiql.helium.flow.port.TransactionManager
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The flow runner is the component every security guarantee routes through, so these tests are
 * about ordering and atomicity rather than happy paths.
 */
class FlowRunnerTest {

    private data class TestCommand(val value: String)

    private val context = FlowContext(
        requestId = RequestId("req_test"),
        actor = Principal.Anonymous,
        now = Instant.parse("2026-08-12T10:00:00Z"),
    )

    /** Records whether the transaction body completed or unwound. */
    private class RecordingTransactionManager : TransactionManager {
        var opened = 0
        var committed = 0
        var rolledBack = 0

        /** Independent transactions commit regardless of what the enclosing one does. */
        var independentCommits = 0

        override suspend fun <T> transaction(block: suspend () -> T): T {
            opened++
            return try {
                block().also { committed++ }
            } catch (error: Throwable) {
                rolledBack++
                throw error
            }
        }

        override suspend fun <T> requiresNew(block: suspend () -> T): T =
            block().also { independentCommits++ }
    }

    private class RecordingOutbox : OutboxPort {
        val published = mutableListOf<DomainEvent>()
        override suspend fun publish(events: List<DomainEvent>, context: OutboxContext) {
            published += events
        }
    }

    private class RecordingAudit : AuditPort {
        val entries = mutableListOf<AuditEntry>()
        override suspend fun record(entry: AuditEntry) {
            entries += entry
        }
    }

    private fun runner(
        transactions: TransactionManager = RecordingTransactionManager(),
        outbox: OutboxPort = RecordingOutbox(),
        audit: AuditPort = RecordingAudit(),
    ) = FlowRunner(transactions, outbox, audit)

    @Test
    fun `successful flow runs steps then commit actions then effects`(): Unit = runTest {
        val order = mutableListOf<String>()
        val outbox = RecordingOutbox()
        val audit = RecordingAudit()

        val flow = flow<TestCommand, String>(FlowId("test.success")) {
            require(requirement("always") { _, _ -> order += "requirement"; RequirementResult.Satisfied })
            step(step("first") { _, _, state -> order += "step1"; state[resultKey] = "one"; StepResult.Continue })
            step(step("second") { _, _, _ -> order += "step2"; StepResult.Continue })
            commitAction(commitAction("commit") { _, _, _ -> order += "commit" })
            effect(
                effect("effect") { _, _, _ ->
                    order += "effect"
                    listOf(DomainEvent.UserRegistered(dev.kamiql.helium.domain.common.UserId.random()))
                },
            )
            result { state -> state.require(resultKey) }
        }

        val result = runner(outbox = outbox, audit = audit).execute(flow, TestCommand("x"), context)

        assertIs<FlowResult.Success<String>>(result)
        assertEquals("one", result.value)
        assertEquals(listOf("requirement", "step1", "step2", "commit", "effect"), order)
        assertEquals(1, outbox.published.size)
        assertEquals(AuditOutcome.SUCCESS, audit.entries.single().outcome)
    }

    @Test
    fun `a rejected requirement never opens a transaction`(): Unit = runTest {
        val transactions = RecordingTransactionManager()
        var stepRan = false

        val flow = flow<TestCommand, String>(FlowId("test.rejected")) {
            require(requirement("deny") { _, _ -> RequirementResult.Rejected(AuthError.Forbidden("nope")) })
            step(step("never") { _, _, _ -> stepRan = true; StepResult.Continue })
            result { "unreachable" }
        }

        val result = runner(transactions).execute(flow, TestCommand("x"), context)

        assertIs<FlowResult.Failure>(result)
        assertEquals("forbidden", result.error.code)
        assertFalse(stepRan, "steps must not run after a rejection")
        // The critical assertion: a rejection cannot have written anything, because no
        // transaction was ever opened.
        assertEquals(0, transactions.opened)
    }

    @Test
    fun `a failing step rolls the transaction back`(): Unit = runTest {
        val transactions = RecordingTransactionManager()
        val outbox = RecordingOutbox()

        val flow = flow<TestCommand, String>(FlowId("test.step-fails")) {
            step(step("writes") { _, _, _ -> StepResult.Continue })
            step(step("fails") { _, _, _ -> StepResult.Fail(AuthError.Conflict) })
            effect(effect("never") { _, _, _ -> error("effects must not run on failure") })
            result { "unreachable" }
        }

        val result = runner(transactions, outbox).execute(flow, TestCommand("x"), context)

        assertIs<FlowResult.Failure>(result)
        assertEquals("conflict", result.error.code)
        assertEquals(1, transactions.opened)
        // This is the property that makes partial application impossible.
        assertEquals(1, transactions.rolledBack)
        assertEquals(0, transactions.committed)
        assertTrue(outbox.published.isEmpty(), "no outbox events may survive a rollback")
    }

    @Test
    fun `a challenge also unwinds the transaction`(): Unit = runTest {
        val transactions = RecordingTransactionManager()

        val flow = flow<TestCommand, String>(FlowId("test.challenge")) {
            step(
                step("challenge") { _, _, _ ->
                    StepResult.Challenge(
                        ChallengeDescriptor(
                            code = ChallengeDescriptor.MFA_REQUIRED,
                            transactionId = TransactionId("tx_1"),
                            expiresAt = context.now.plusSeconds(300),
                            methods = setOf("totp"),
                        ),
                    )
                },
            )
            result { "unreachable" }
        }

        val result = runner(transactions).execute(flow, TestCommand("x"), context)

        val challenge = assertIs<FlowResult.Challenge>(result)
        assertEquals("mfa_required", challenge.code)
        assertEquals(setOf("totp"), challenge.methods)
        assertEquals(1, transactions.rolledBack)
    }

    @Test
    fun `a domain exception from a repository becomes a failure result`(): Unit = runTest {
        val transactions = RecordingTransactionManager()

        val flow = flow<TestCommand, String>(FlowId("test.throws")) {
            step(step("throws") { _, _, _ -> throw AuthErrorException(AuthError.IdentityAlreadyLinked) })
            result { "unreachable" }
        }

        val result = runner(transactions).execute(flow, TestCommand("x"), context)

        assertIs<FlowResult.Failure>(result)
        assertEquals("identity_already_linked", result.error.code)
        assertEquals(1, transactions.rolledBack)
    }

    @Test
    fun `an unexpected exception is not leaked to the caller`(): Unit = runTest {
        val flow = flow<TestCommand, String>(FlowId("test.boom")) {
            step(step("boom") { _, _, _ -> throw IllegalStateException("connection string: postgres://user:pw@host") })
            result { "unreachable" }
        }

        val result = runner().execute(flow, TestCommand("x"), context)

        assertIs<FlowResult.Failure>(result)
        // Generic code, and nothing from the exception message reaches the response.
        assertEquals("temporarily_unavailable", result.error.code)
        assertFalse(result.error.detail.contains("postgres"))
    }

    @Test
    fun `a failure is audited even though the transaction rolled back`(): Unit = runTest {
        val audit = RecordingAudit()

        val flow = flow<TestCommand, String>(FlowId("test.audit-on-failure")) {
            step(step("fails") { _, _, _ -> StepResult.Fail(AuthError.InvalidCredentials) })
            result { "unreachable" }
        }

        runner(audit = audit).execute(flow, TestCommand("x"), context)

        val entry = audit.entries.single()
        assertEquals(AuditOutcome.FAILURE, entry.outcome)
        assertEquals("invalid_credentials", entry.metadata["error"])
    }

    @Test
    fun `idempotency key is required when the flow demands one`(): Unit = runTest {
        val flow = flow<TestCommand, String>(FlowId("test.idempotent")) {
            idempotency(IdempotencyPolicy.Required)
            step(step("never") { _, _, _ -> StepResult.Continue })
            result { "unreachable" }
        }

        val result = runner().execute(flow, TestCommand("x"), context)

        assertIs<FlowResult.Failure>(result)
        val error = assertIs<AuthError.ValidationFailed>(result.error)
        assertEquals("required", error.fields["idempotency_key"])
    }

    @Test
    fun `sensitive state never reaches the audit metadata`(): Unit = runTest {
        val audit = RecordingAudit()
        val secretKey = FlowStateKey<String>("password", sensitive = true)
        val plainKey = FlowStateKey<String>("username")

        val flow = flow<TestCommand, String>(FlowId("test.redaction")) {
            step(
                step("populate") { _, _, state ->
                    state[secretKey] = "hunter2"
                    state[plainKey] = "alice"
                    StepResult.Continue
                },
            )
            result { "ok" }
        }

        runner(audit = audit).execute(flow, TestCommand("x"), context)

        val metadata = audit.entries.single().metadata
        assertEquals("alice", metadata["username"])
        assertFalse(metadata.containsKey("password"))
        assertFalse(metadata.values.any { it.contains("hunter2") })
    }

    private companion object {
        val resultKey = FlowStateKey<String>("result")
    }
}
