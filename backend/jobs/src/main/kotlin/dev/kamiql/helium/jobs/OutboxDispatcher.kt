package dev.kamiql.helium.jobs

import dev.kamiql.helium.domain.crypto.HeliumClock
import dev.kamiql.helium.persistence.repository.ClaimedOutboxEvent
import dev.kamiql.helium.persistence.repository.OutboxDispatchRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Duration
import kotlin.math.min
import kotlin.math.pow

/**
 * Handles one kind of outbox event.
 *
 * Handlers must be **idempotent**: delivery is at-least-once by construction, and a handler
 * that sends a second mail on a retry is a handler that spams users during an incident.
 */
interface OutboxHandler {

    /** Event types this handler consumes. */
    val eventTypes: Set<String>

    /**
     * @throws Exception to signal a retryable failure; the dispatcher backs off and tries
     *         again. Return normally for both success and permanent, unretryable failure — a
     *         malformed payload will never become well-formed.
     */
    suspend fun handle(event: OutboxEventPayload)
}

/**
 * A decoded outbox event.
 *
 * @param fields flat string map, exactly what [dev.kamiql.helium.persistence.repository.OutboxRepositoryImpl]
 *        wrote. Never contains a secret.
 */
data class OutboxEventPayload(
    val id: java.util.UUID,
    val eventType: String,
    val aggregateType: String,
    val aggregateId: String,
    val fields: Map<String, String>,
    val attempts: Int,
)

/**
 * Delivers transactional-outbox events after commit.
 *
 * This is the other half of the pattern concept §2.4 requires: the writer records the intent
 * inside the transaction, and this worker performs the side effect outside it. The two are
 * decoupled precisely so a slow SMTP server cannot hold a database transaction open, and so a
 * mail failure cannot roll back a password change that already happened.
 *
 * @param claimLease how long a claimed event is hidden from other workers. Must exceed the
 *        slowest handler, or two workers will process the same event concurrently.
 * @param maxAttempts after this many failures the event stops being retried and is left in the
 *        table with its error for an operator to look at. Dropping it silently would hide a
 *        systemic delivery failure.
 */
class OutboxDispatcher(
    private val repository: OutboxDispatchRepository,
    private val handlers: List<OutboxHandler>,
    private val clock: HeliumClock,
    private val pollInterval: Duration = Duration.ofSeconds(2),
    private val batchSize: Int = 50,
    private val claimLease: Duration = Duration.ofMinutes(2),
    private val maxAttempts: Int = 12,
) {

    private val log = LoggerFactory.getLogger(OutboxDispatcher::class.java)
    private val json = Json { ignoreUnknownKeys = true }
    private val byType: Map<String, List<OutboxHandler>> =
        handlers.flatMap { handler -> handler.eventTypes.map { it to handler } }
            .groupBy({ it.first }, { it.second })

    /**
     * Runs until the scope is cancelled.
     *
     * Safe to run on several instances at once: claiming is an optimistic conditional UPDATE,
     * so two workers racing for the same row means one of them simply moves on.
     */
    fun start(scope: CoroutineScope): Job = scope.launch {
        log.info("outbox dispatcher started with {} handler(s)", handlers.size)
        while (isActive) {
            val processed = runCatching { drainOnce() }
                .onFailure { log.error("outbox poll failed", it) }
                .getOrDefault(0)

            // Only idle when there was nothing to do; a full batch means keep going.
            if (processed < batchSize) {
                delay(pollInterval.toMillis())
            }
        }
    }

    /** One poll cycle. Exposed so tests can drive the dispatcher deterministically. */
    suspend fun drainOnce(): Int {
        val now = clock.now()
        val claimed = repository.claim(now, batchSize, claimLease)
        claimed.forEach { event -> deliver(event) }
        return claimed.size
    }

    private suspend fun deliver(event: ClaimedOutboxEvent) {
        val payload = decode(event)
        if (payload == null) {
            // Unparseable payload will never parse. Mark it done so it stops consuming
            // attempts, and leave a loud log line — this is a bug, not a transient fault.
            log.error("outbox event {} has an undecodable payload; dropping", event.id)
            repository.markProcessed(event.id, clock.now())
            return
        }

        val matching = byType[event.eventType].orEmpty()
        if (matching.isEmpty()) {
            // Not every event needs a side effect; many exist purely as an audit signal.
            repository.markProcessed(event.id, clock.now())
            return
        }

        try {
            // NonCancellable: a handler that has already sent a mail must be allowed to record
            // that fact, even if the worker is shutting down. Otherwise the event is redelivered
            // and the user gets the mail twice.
            withContext(NonCancellable) {
                matching.forEach { it.handle(payload) }
                repository.markProcessed(event.id, clock.now())
            }
        } catch (error: Exception) {
            val attempts = event.attempts
            if (attempts >= maxAttempts) {
                log.error(
                    "outbox event {} ({}) exhausted {} attempts; leaving for manual inspection",
                    event.id, event.eventType, attempts, error,
                )
                // Push it far into the future rather than deleting: the row is the evidence.
                repository.markFailed(event.id, clock.now(), describe(error), Duration.ofDays(1))
            } else {
                val backoff = backoffFor(attempts)
                log.warn(
                    "outbox event {} ({}) failed on attempt {}; retrying in {}s",
                    event.id, event.eventType, attempts, backoff.seconds,
                )
                repository.markFailed(event.id, clock.now(), describe(error), backoff)
            }
        }
    }

    /**
     * Exponential backoff, capped.
     *
     * Capped at 15 minutes so a provider that comes back after an hour is picked up promptly
     * rather than after a day of doubling.
     */
    private fun backoffFor(attempts: Int): Duration {
        val seconds = min(2.0.pow(attempts.coerceAtMost(10)).toLong(), Duration.ofMinutes(15).seconds)
        return Duration.ofSeconds(seconds.coerceAtLeast(1))
    }

    /** Exception class and message only — a cause chain can carry a provider response body. */
    private fun describe(error: Throwable): String =
        "${error::class.simpleName}: ${error.message?.take(200).orEmpty()}"

    private fun decode(event: ClaimedOutboxEvent): OutboxEventPayload? = runCatching {
        val obj = json.decodeFromString(JsonObject.serializer(), event.payload)
        OutboxEventPayload(
            id = event.id,
            eventType = event.eventType,
            aggregateType = event.aggregateType,
            aggregateId = event.aggregateId,
            fields = obj.mapValues { (_, value) -> value.jsonPrimitive.content },
            attempts = event.attempts,
        )
    }.getOrNull()
}
