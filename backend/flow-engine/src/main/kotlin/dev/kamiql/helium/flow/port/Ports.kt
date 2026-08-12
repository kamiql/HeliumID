package dev.kamiql.helium.flow.port

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.flow.FlowId
import java.time.Duration
import java.time.Instant

/**
 * Owns transaction scope.
 *
 * Repositories join the ambient transaction rather than opening their own, which is what makes
 * "all of it or none of it" true for a flow. Nesting is join-not-nest: an inner call
 * participates in the outer transaction.
 */
interface TransactionManager {
    suspend fun <T> transaction(block: suspend () -> T): T

    /**
     * Runs [block] in a **new, independent** transaction that commits on its own, even when the
     * enclosing transaction later rolls back.
     *
     * Needed for the rare case where a security action must outlive the failure that triggered
     * it. The motivating example is refresh-token reuse detection: the flow discovers a replayed
     * token, revokes the whole family, and then *fails the request*. If the revocation shared the
     * failing transaction it would be rolled back with it, and the attacker's replay would have
     * cost them nothing (concept §4.3).
     *
     * Use sparingly and deliberately. Every call here is a place where "all or nothing" no longer
     * holds, so the block must be small, idempotent, and safe to have committed even if the rest
     * of the request did not happen.
     */
    suspend fun <T> requiresNew(block: suspend () -> T): T
}

/**
 * Writes domain events to the transactional outbox.
 *
 * Called **inside** the flow's transaction. If the transaction rolls back, the events vanish
 * with it — there is no "sent an email about a password change that never happened".
 */
interface OutboxPort {
    suspend fun publish(events: List<DomainEvent>, context: OutboxContext)
}

data class OutboxContext(
    val requestId: RequestId,
    val occurredAt: Instant,
)

/**
 * Writes security audit rows, also inside the transaction.
 *
 * Concept §7.5 lists what must never appear here: passwords, tokens, cookies, TOTP codes,
 * reset tokens, authorization codes, full provider responses. [AuditEntry.metadata] is
 * therefore restricted to short, non-sensitive strings and is reviewed at every call site.
 */
interface AuditPort {
    suspend fun record(entry: AuditEntry)
}

data class AuditEntry(
    val eventType: String,
    val outcome: AuditOutcome,
    val actorUserId: UserId?,
    val subjectUserId: UserId?,
    val clientId: ClientId?,
    val requestId: RequestId,
    /** Hashed, never raw. Correlates activity without storing an identifier. */
    val ipHash: String?,
    val userAgentHash: String?,
    val occurredAt: Instant,
    val metadata: Map<String, String> = emptyMap(),
)

enum class AuditOutcome { SUCCESS, FAILURE, CHALLENGE }

/**
 * Distributed rate limiting.
 *
 * Concept §4.6: limit by several dimensions at once, and degrade conservatively. When the
 * backing store is unreachable, implementations must fail **closed** for authentication
 * endpoints rather than silently allowing unlimited attempts.
 */
interface RateLimiter {

    /**
     * Consumes one unit against [key].
     *
     * @return [RateLimitDecision.Allowed] or [RateLimitDecision.Limited] with the retry delay.
     */
    suspend fun consume(key: RateLimitKey, limit: RateLimit): RateLimitDecision

    /** Called after a successful authentication so a legitimate user is not punished. */
    suspend fun reset(key: RateLimitKey)
}

/**
 * @param dimension what is being limited (`login.account`, `login.ip`, `reset.email`, …).
 * @param value the already-normalized and, where it is personal data, hashed discriminator.
 */
data class RateLimitKey(val dimension: String, val value: String)

data class RateLimit(val permits: Int, val window: Duration) {
    companion object {
        // Concept §4.6 starting limits.
        val LOGIN_PER_ACCOUNT_AND_IP = RateLimit(5, Duration.ofMinutes(10))
        val LOGIN_PER_IP = RateLimit(20, Duration.ofMinutes(10))
        val PASSWORD_RESET = RateLimit(3, Duration.ofHours(1))
        val TOTP_VERIFY = RateLimit(5, Duration.ofMinutes(5))
        val EMAIL_VERIFICATION = RateLimit(5, Duration.ofMinutes(10))
        val OAUTH_CALLBACK_FAILURES = RateLimit(20, Duration.ofMinutes(10))
        val TOKEN_ENDPOINT = RateLimit(60, Duration.ofMinutes(1))
        val REGISTRATION = RateLimit(5, Duration.ofHours(1))
    }
}

sealed interface RateLimitDecision {
    data class Allowed(val remaining: Int) : RateLimitDecision
    data class Limited(val retryAfter: Duration) : RateLimitDecision
}

/**
 * Short-lived, single-use server-side state for a security transaction: MFA challenges, OAuth
 * `state`/PKCE for outbound provider calls, provider linking, consent.
 *
 * Redis-backed in production. Correctness does not depend on the cache surviving: losing an
 * entry makes the transaction fail closed and the user starts again (concept §3.1).
 */
interface SecurityTransactionStore {

    /** @param ttl short by design; see [dev.kamiql.helium.domain.policy.Lifetimes]. */
    suspend fun put(id: TransactionId, kind: String, payload: String, ttl: Duration)

    suspend fun peek(id: TransactionId, kind: String): String?

    /**
     * Atomically reads and deletes.
     *
     * The atomicity is the security property: it is what makes an authorization `state`, an
     * MFA transaction and a linking transaction genuinely single-use even under concurrent
     * requests.
     */
    suspend fun take(id: TransactionId, kind: String): String?

    suspend fun delete(id: TransactionId, kind: String)

    /** Bounded counter used for per-transaction attempt limits. */
    suspend fun increment(id: TransactionId, kind: String, ttl: Duration): Long
}

/**
 * Replay protection for retriable operations (concept §2.5).
 *
 * The record stores a hash of the request so that the same key with a *different* payload is a
 * conflict rather than a silent replay of the wrong response.
 */
interface IdempotencyStore {

    suspend fun begin(record: IdempotencyRequest): IdempotencyState

    suspend fun complete(key: String, flowId: FlowId, responseHash: String, response: String, at: Instant)

    suspend fun fail(key: String, flowId: FlowId, at: Instant)
}

data class IdempotencyRequest(
    val key: String,
    val flowId: FlowId,
    val clientId: ClientId?,
    val userId: UserId?,
    val requestHash: String,
    val expiresAt: Instant,
)

sealed interface IdempotencyState {
    /** First time this key has been seen; proceed. */
    data object Fresh : IdempotencyState

    /** Completed earlier with the same payload; replay [response] verbatim. */
    data class Replay(val response: String) : IdempotencyState

    /** Same key, different payload. */
    data object Conflict : IdempotencyState

    /** An identical request is still running. The caller should retry shortly. */
    data object InProgress : IdempotencyState
}

/**
 * Emits counters and timers. Concept §7.5 names the metrics; the important constraint is that
 * labels stay low cardinality — never an email address, username or token id.
 */
interface MetricsPort {
    fun counter(name: String, tags: Map<String, String> = emptyMap(), amount: Double = 1.0)
    fun timer(name: String, durationNanos: Long, tags: Map<String, String> = emptyMap())

    /** No-op implementation for tests and for modules that do not care. */
    object NoOp : MetricsPort {
        override fun counter(name: String, tags: Map<String, String>, amount: Double) = Unit
        override fun timer(name: String, durationNanos: Long, tags: Map<String, String>) = Unit
    }
}
