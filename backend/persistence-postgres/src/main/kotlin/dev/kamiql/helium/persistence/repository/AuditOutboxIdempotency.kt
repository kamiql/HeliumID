package dev.kamiql.helium.persistence.repository

import dev.kamiql.helium.domain.common.AuditEventId
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.OutboxEventId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.port.AuditEntry
import dev.kamiql.helium.flow.port.AuditOutcome
import dev.kamiql.helium.flow.port.AuditPort
import dev.kamiql.helium.flow.port.IdempotencyRequest
import dev.kamiql.helium.flow.port.IdempotencyState
import dev.kamiql.helium.flow.port.IdempotencyStore
import dev.kamiql.helium.flow.port.OutboxContext
import dev.kamiql.helium.flow.port.OutboxPort
import dev.kamiql.helium.persistence.AuditLogsTable
import dev.kamiql.helium.persistence.IdempotencyRecordsTable
import dev.kamiql.helium.persistence.OutboxEventsTable
import dev.kamiql.helium.persistence.dbQuery
import dev.kamiql.helium.persistence.toDb
import dev.kamiql.helium.persistence.toInstantUtc
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import java.time.Instant

private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }

/**
 * Writes audit rows.
 *
 * Runs inside the caller's transaction for successful flows, so the record and the change it
 * describes commit together. Failure rows are written by the runner outside the (rolled back)
 * transaction, because a record of a rejected attempt must survive the rejection.
 */
class AuditRepositoryImpl(private val database: Database) : AuditPort {

    override suspend fun record(entry: AuditEntry) {
        dbQuery(database) {
            AuditLogsTable.insert { row ->
                row[id] = AuditEventId.random().value
                row[eventType] = entry.eventType
                row[outcome] = entry.outcome.name
                row[actorUserId] = entry.actorUserId?.value
                row[subjectUserId] = entry.subjectUserId?.value
                row[clientId] = entry.clientId?.value
                row[requestId] = entry.requestId.value
                row[ipHash] = entry.ipHash
                row[userAgentHash] = entry.userAgentHash
                row[metadata] = entry.metadata.toJsonObjectString()
                row[createdAt] = entry.occurredAt.toDb()
            }
        }
    }
}

/** Read side of the audit trail, for the admin UI. */
class AuditQueryRepository(private val database: Database) {

    data class AuditRecord(
        val id: java.util.UUID,
        val eventType: String,
        val outcome: AuditOutcome,
        val actorUserId: UserId?,
        val subjectUserId: UserId?,
        val clientId: ClientId?,
        val requestId: RequestId,
        val metadata: Map<String, String>,
        val createdAt: Instant,
    )

    suspend fun query(
        subjectUserId: UserId? = null,
        eventType: String? = null,
        limit: Int = 100,
        offset: Long = 0,
    ): dev.kamiql.helium.domain.repository.Page<AuditRecord> = dbQuery(database) {
        val condition = {
            var op: Op<Boolean> = Op.TRUE
            subjectUserId?.let { op = op and (AuditLogsTable.subjectUserId eq it.value) }
            eventType?.let { op = op and (AuditLogsTable.eventType eq it) }
            op
        }
        val total = AuditLogsTable.selectAll().where(condition()).count()
        val items = AuditLogsTable.selectAll()
            .where(condition())
            .orderBy(AuditLogsTable.createdAt, SortOrder.DESC)
            .limit(limit)
            .offset(offset)
            .map { row ->
                AuditRecord(
                    id = row[AuditLogsTable.id],
                    eventType = row[AuditLogsTable.eventType],
                    outcome = AuditOutcome.valueOf(row[AuditLogsTable.outcome]),
                    actorUserId = row[AuditLogsTable.actorUserId]?.let(::UserId),
                    subjectUserId = row[AuditLogsTable.subjectUserId]?.let(::UserId),
                    clientId = row[AuditLogsTable.clientId]?.let(::ClientId),
                    requestId = RequestId(row[AuditLogsTable.requestId]),
                    metadata = row[AuditLogsTable.metadata].parseJsonObject(),
                    createdAt = row[AuditLogsTable.createdAt].toInstantUtc(),
                )
            }
        dev.kamiql.helium.domain.repository.Page(items, total, limit, offset)
    }
}

/**
 * Transactional outbox writer.
 *
 * The payload is deliberately small — identifiers and enum values. Recipients that need more
 * look it up at delivery time, which also means a delivery that happens minutes later sends
 * current data rather than a stale snapshot.
 */
class OutboxRepositoryImpl(private val database: Database) : OutboxPort {

    override suspend fun publish(events: List<DomainEvent>, context: OutboxContext) {
        dbQuery(database) {
            events.forEach { event ->
                OutboxEventsTable.insert { row ->
                    row[id] = OutboxEventId.random().value
                    row[eventType] = event.type
                    row[aggregateType] = event.aggregateType()
                    row[aggregateId] = event.aggregateId()
                    row[payload] = event.toPayload(context)
                    row[attempts] = 0
                    row[availableAt] = context.occurredAt.toDb()
                    row[processedAt] = null
                    row[createdAt] = context.occurredAt.toDb()
                }
            }
        }
    }

    private fun DomainEvent.aggregateType(): String = when (this) {
        is DomainEvent.ClientRegistered, is DomainEvent.ClientSecretRotated -> "client"
        else -> "user"
    }

    private fun DomainEvent.aggregateId(): String = when (this) {
        is DomainEvent.ClientRegistered -> clientId.value
        is DomainEvent.ClientSecretRotated -> clientId.value
        else -> userId?.value?.toString() ?: "unknown"
    }

    /**
     * Reflection-free payload rendering.
     *
     * `kotlinx.serialization` on a sealed hierarchy would work, but an explicit `when` means a
     * new event type cannot accidentally serialize a field that should not leave the process.
     */
    private fun DomainEvent.toPayload(context: OutboxContext): String {
        val fields = mutableMapOf<String, String>(
            "type" to type,
            "request_id" to context.requestId.value,
            "occurred_at" to context.occurredAt.toString(),
        )
        userId?.let { fields["user_id"] = it.value.toString() }
        when (this) {
            is DomainEvent.EmailVerificationRequested -> {
                fields["token_id"] = tokenId
                fields["purpose"] = purpose.token
            }
            is DomainEvent.PasswordResetRequested -> fields["token_id"] = tokenId
            is DomainEvent.EmailChanged -> fields["previous_email"] = previousEmailNormalized
            is DomainEvent.AccountStatusChanged -> fields["new_status"] = newStatus
            is DomainEvent.LoginSucceeded -> {
                fields["new_device"] = newDevice.toString()
                sessionId?.let { fields["session_id"] = it.value.toString() }
                clientId?.let { fields["client_id"] = it.value }
            }
            is DomainEvent.LoginFailed -> fields["reason"] = reason
            is DomainEvent.SessionRevoked -> {
                fields["reason"] = reason.name
                fields["count"] = count.toString()
            }
            is DomainEvent.MfaEnrolled -> fields["method"] = method.token
            is DomainEvent.MfaDisabled -> fields["method"] = method.token
            is DomainEvent.RecoveryCodeUsed -> fields["remaining"] = remaining.toString()
            is DomainEvent.ProviderLinked -> fields["provider"] = provider.value
            is DomainEvent.ProviderUnlinked -> fields["provider"] = provider.value
            is DomainEvent.RefreshTokenReuseDetected -> fields["client_id"] = clientId.value
            is DomainEvent.ClientRegistered -> fields["client_id"] = clientId.value
            is DomainEvent.ClientSecretRotated -> fields["client_id"] = clientId.value
            else -> Unit
        }
        return fields.toJsonObjectString()
    }
}

/**
 * Postgres-backed idempotency records (concept §2.5).
 *
 * The primary key on `(idempotency_key, flow_id)` is what makes [begin] atomic: two concurrent
 * requests with the same key race on the insert, and the loser learns the operation is already
 * in progress instead of running it a second time.
 */
class IdempotencyStoreImpl(private val database: Database) : IdempotencyStore {

    override suspend fun begin(record: IdempotencyRequest): IdempotencyState = dbQuery(database) {
        val existing = IdempotencyRecordsTable.selectAll()
            .where {
                (IdempotencyRecordsTable.idempotencyKey eq record.key) and
                    (IdempotencyRecordsTable.flowId eq record.flowId.value)
            }
            .firstOrNull()

        if (existing != null) {
            return@dbQuery when {
                existing[IdempotencyRecordsTable.requestHash] != record.requestHash ->
                    IdempotencyState.Conflict

                existing[IdempotencyRecordsTable.status] == "COMPLETED" ->
                    IdempotencyState.Replay(existing[IdempotencyRecordsTable.responseBody].orEmpty())

                existing[IdempotencyRecordsTable.status] == "IN_PROGRESS" ->
                    IdempotencyState.InProgress

                // A previously failed attempt may be retried; clear it and start over.
                else -> {
                    IdempotencyRecordsTable.deleteWhere {
                        (idempotencyKey eq record.key) and (flowId eq record.flowId.value)
                    }
                    insertInProgress(record)
                    IdempotencyState.Fresh
                }
            }
        }

        try {
            insertInProgress(record)
            IdempotencyState.Fresh
        } catch (_: org.jetbrains.exposed.v1.exceptions.ExposedSQLException) {
            // Lost the insert race with a concurrent identical request.
            IdempotencyState.InProgress
        }
    }

    override suspend fun complete(
        key: String,
        flowId: FlowId,
        responseHash: String,
        response: String,
        at: Instant,
    ) {
        dbQuery(database) {
            IdempotencyRecordsTable.update(
                where = {
                    (IdempotencyRecordsTable.idempotencyKey eq key) and
                        (IdempotencyRecordsTable.flowId eq flowId.value)
                },
            ) { row ->
                row[status] = "COMPLETED"
                row[IdempotencyRecordsTable.responseHash] = responseHash
                row[responseBody] = response
                row[completedAt] = at.toDb()
            }
        }
    }

    override suspend fun fail(key: String, flowId: FlowId, at: Instant) {
        dbQuery(database) {
            IdempotencyRecordsTable.update(
                where = {
                    (IdempotencyRecordsTable.idempotencyKey eq key) and
                        (IdempotencyRecordsTable.flowId eq flowId.value)
                },
            ) { row ->
                row[status] = "FAILED"
                row[completedAt] = at.toDb()
            }
        }
    }

    suspend fun deleteExpired(before: Instant): Int = dbQuery(database) {
        IdempotencyRecordsTable.deleteWhere { expiresAt less before.toDb() }
    }

    private fun insertInProgress(record: IdempotencyRequest) {
        IdempotencyRecordsTable.insert { row ->
            row[idempotencyKey] = record.key
            row[flowId] = record.flowId.value
            row[clientId] = record.clientId?.value
            row[userId] = record.userId?.value
            row[requestHash] = record.requestHash
            row[status] = "IN_PROGRESS"
            row[createdAt] = Instant.now().toDb()
            row[expiresAt] = record.expiresAt.toDb()
        }
    }
}

private fun Map<String, String>.toJsonObjectString(): String =
    json.encodeToString(JsonObject.serializer(), JsonObject(mapValues { JsonPrimitive(it.value) }))

private fun String.parseJsonObject(): Map<String, String> =
    runCatching {
        json.decodeFromString(JsonObject.serializer(), this)
            .mapValues { (_, value) -> value.toString().trim('"') }
    }.getOrElse { emptyMap() }
