package dev.kamiql.helium.persistence.repository

import dev.kamiql.helium.persistence.OutboxEventsTable
import dev.kamiql.helium.persistence.dbQuery
import dev.kamiql.helium.persistence.toDb
import dev.kamiql.helium.persistence.toInstantUtc
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import java.time.Duration
import java.time.Instant
import java.util.UUID

/** An outbox row claimed for delivery. */
data class ClaimedOutboxEvent(
    val id: UUID,
    val eventType: String,
    val aggregateType: String,
    val aggregateId: String,
    val payload: String,
    val attempts: Int,
    val createdAt: Instant,
)

/**
 * Claim side of the transactional outbox, used by the `jobs` worker.
 *
 * Claiming is an optimistic conditional UPDATE that pushes `available_at` into the future
 * before the work starts. Two workers can therefore run concurrently: only one `UPDATE` per
 * row reports a row count of 1, and the other simply moves on. This is deliberately *not*
 * `SELECT … FOR UPDATE SKIP LOCKED`, which would hold a row lock for the entire delivery
 * attempt — including the network call — and turn a slow SMTP server into database pressure.
 *
 * Delivery is therefore at-least-once, which is why handlers must be idempotent.
 */
class OutboxDispatchRepository(private val database: Database) {

    /**
     * @param leaseFor how long this worker is assumed to need. A crash after claiming means
     *        the row becomes available again once the lease expires, rather than being lost.
     */
    suspend fun claim(now: Instant, batchSize: Int, leaseFor: Duration): List<ClaimedOutboxEvent> =
        dbQuery(database) {
            val candidates = OutboxEventsTable.select(OutboxEventsTable.id)
                .where {
                    OutboxEventsTable.processedAt.isNull() and
                        (OutboxEventsTable.availableAt lessEq now.toDb())
                }
                .orderBy(OutboxEventsTable.availableAt, SortOrder.ASC)
                .limit(batchSize)
                .map { it[OutboxEventsTable.id] }

            candidates.mapNotNull { id ->
                val claimed = OutboxEventsTable.update(
                    where = {
                        (OutboxEventsTable.id eq id) and
                            OutboxEventsTable.processedAt.isNull() and
                            (OutboxEventsTable.availableAt lessEq now.toDb())
                    },
                ) { row ->
                    row[availableAt] = now.plus(leaseFor).toDb()
                    row[attempts] = attempts + 1
                } > 0

                if (!claimed) return@mapNotNull null

                OutboxEventsTable.selectAll()
                    .where { OutboxEventsTable.id eq id }
                    .firstOrNull()
                    ?.let { row ->
                        ClaimedOutboxEvent(
                            id = row[OutboxEventsTable.id],
                            eventType = row[OutboxEventsTable.eventType],
                            aggregateType = row[OutboxEventsTable.aggregateType],
                            aggregateId = row[OutboxEventsTable.aggregateId],
                            payload = row[OutboxEventsTable.payload],
                            attempts = row[OutboxEventsTable.attempts],
                            createdAt = row[OutboxEventsTable.createdAt].toInstantUtc(),
                        )
                    }
            }
        }

    suspend fun markProcessed(id: UUID, at: Instant) {
        dbQuery(database) {
            OutboxEventsTable.update(where = { OutboxEventsTable.id eq id }) { row ->
                row[processedAt] = at.toDb()
                row[lastError] = null
            }
        }
    }

    /**
     * Records the failure and schedules a retry.
     *
     * @param error truncated hard: an exception message can contain a provider response, and
     *        this column is read by operators.
     */
    suspend fun markFailed(id: UUID, at: Instant, error: String, retryIn: Duration) {
        dbQuery(database) {
            OutboxEventsTable.update(where = { OutboxEventsTable.id eq id }) { row ->
                row[availableAt] = at.plus(retryIn).toDb()
                row[lastError] = error.take(500)
            }
        }
    }

    /** Delivered history is pruned; failures are kept so they stay visible. */
    suspend fun deleteProcessedBefore(before: Instant): Int = dbQuery(database) {
        OutboxEventsTable.deleteWhere {
            processedAt.isNotNull() and (processedAt less before.toDb())
        }
    }

    /** Rows that have exhausted their retries, for alerting. */
    suspend fun countStuck(minAttempts: Int): Long = dbQuery(database) {
        OutboxEventsTable.selectAll()
            .where { OutboxEventsTable.processedAt.isNull() and (OutboxEventsTable.attempts greaterEq minAttempts) }
            .count()
    }
}
