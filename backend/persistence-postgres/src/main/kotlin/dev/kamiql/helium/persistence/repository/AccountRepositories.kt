package dev.kamiql.helium.persistence.repository

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.ExternalIdentityId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.credential.PasswordCredential
import dev.kamiql.helium.domain.credential.PasswordHash
import dev.kamiql.helium.domain.credential.PasswordHashParameters
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.error.AuthErrorException
import dev.kamiql.helium.domain.identity.ExternalIdentity
import dev.kamiql.helium.domain.identity.Issuer
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.identity.ProviderSubject
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.repository.ExternalIdentityRepository
import dev.kamiql.helium.domain.repository.PasswordCredentialRepository
import dev.kamiql.helium.domain.repository.RoleRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.persistence.ExternalIdentitiesTable
import dev.kamiql.helium.persistence.PasswordCredentialsTable
import dev.kamiql.helium.persistence.RolePermissionsTable
import dev.kamiql.helium.persistence.RolesTable
import dev.kamiql.helium.persistence.SessionsTable
import dev.kamiql.helium.persistence.UserRolesTable
import dev.kamiql.helium.persistence.dbQuery
import dev.kamiql.helium.persistence.toDb
import dev.kamiql.helium.persistence.toInstantUtc
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import org.jetbrains.exposed.v1.jdbc.upsert
import java.time.Instant

/** Comma-separated storage for small closed sets. A join table would be ceremony without value. */
internal fun Set<String>.toCsv(): String = joinToString(",")

internal fun String.fromCsv(): Set<String> =
    split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }

class PasswordCredentialRepositoryImpl(private val database: Database) : PasswordCredentialRepository {

    override suspend fun findByUserId(userId: UserId): PasswordCredential? = dbQuery(database) {
        PasswordCredentialsTable.selectAll()
            .where { PasswordCredentialsTable.userId eq userId.value }
            .firstOrNull()
            ?.let { row ->
                PasswordCredential(
                    userId = userId,
                    hash = PasswordHash(
                        algorithm = row[PasswordCredentialsTable.algorithm],
                        encoded = row[PasswordCredentialsTable.passwordHash],
                        parameters = decodeParameters(row[PasswordCredentialsTable.parameters]),
                    ),
                    changedAt = row[PasswordCredentialsTable.changedAt].toInstantUtc(),
                    createdAt = row[PasswordCredentialsTable.createdAt].toInstantUtc(),
                )
            }
    }

    /** Upsert, because setting a first password and changing one are the same write. */
    override suspend fun upsert(userId: UserId, hash: PasswordHash, at: Instant) {
        dbQuery(database) {
            PasswordCredentialsTable.upsert(PasswordCredentialsTable.userId) { row ->
                row[PasswordCredentialsTable.userId] = userId.value
                row[passwordHash] = hash.encoded
                row[algorithm] = hash.algorithm
                row[parameters] = encodeParameters(hash.parameters)
                row[changedAt] = at.toDb()
                row[createdAt] = at.toDb()
            }
        }
    }

    override suspend fun delete(userId: UserId) {
        dbQuery(database) {
            PasswordCredentialsTable.deleteWhere { PasswordCredentialsTable.userId eq userId.value }
        }
    }

    private fun encodeParameters(parameters: PasswordHashParameters): String = json.encodeToString(
        StoredParameters(
            parameters.memoryKib, parameters.iterations, parameters.parallelism,
            parameters.saltLength, parameters.hashLength, parameters.pepperVersion,
        ),
    )

    private fun decodeParameters(raw: String): PasswordHashParameters {
        val stored = json.decodeFromString<StoredParameters>(raw)
        return PasswordHashParameters(
            memoryKib = stored.memoryKib,
            iterations = stored.iterations,
            parallelism = stored.parallelism,
            saltLength = stored.saltLength,
            hashLength = stored.hashLength,
            pepperVersion = stored.pepperVersion,
        )
    }

    @kotlinx.serialization.Serializable
    private data class StoredParameters(
        val memoryKib: Int,
        val iterations: Int,
        val parallelism: Int,
        val saltLength: Int,
        val hashLength: Int,
        val pepperVersion: Int,
    )
}

class RoleRepositoryImpl(private val database: Database) : RoleRepository {

    override suspend fun listRoles(): List<Role> = dbQuery(database) {
        val permissions = RolePermissionsTable.selectAll()
            .groupBy({ it[RolePermissionsTable.roleName] }) { Permission(it[RolePermissionsTable.permission]) }
        RolesTable.selectAll().map { row -> row.toRole(permissions[row[RolesTable.name]].orEmpty().toSet()) }
    }

    override suspend fun findRole(name: String): Role? = dbQuery(database) {
        val row = RolesTable.selectAll().where { RolesTable.name eq name }.firstOrNull() ?: return@dbQuery null
        val permissions = RolePermissionsTable.select(RolePermissionsTable.permission)
            .where { RolePermissionsTable.roleName eq name }
            .map { Permission(it[RolePermissionsTable.permission]) }
            .toSet()
        row.toRole(permissions)
    }

    override suspend fun upsertRole(role: Role): Role = dbQuery(database) {
        val now = Instant.now()
        RolesTable.upsert(RolesTable.name) { row ->
            row[name] = role.name
            row[description] = role.description
            row[color] = role.color
            row[builtIn] = role.builtIn
            row[createdAt] = now.toDb()
            row[updatedAt] = now.toDb()
        }
        RolePermissionsTable.deleteWhere { roleName eq role.name }
        role.permissions.forEach { permission ->
            RolePermissionsTable.insert { row ->
                row[roleName] = role.name
                row[RolePermissionsTable.permission] = permission.value
            }
        }
        role
    }

    /** Built-in roles are protected here as well as in the API, so no path can delete them. */
    override suspend fun deleteRole(name: String): Boolean = dbQuery(database) {
        val role = RolesTable.selectAll().where { RolesTable.name eq name }.firstOrNull()
            ?: return@dbQuery false
        if (role[RolesTable.builtIn]) throw AuthErrorException(AuthError.Conflict)
        RolesTable.deleteWhere { RolesTable.name eq name } > 0
    }

    override suspend fun rolesOf(userId: UserId): Set<String> = dbQuery(database) {
        UserRolesTable.select(UserRolesTable.roleName)
            .where { UserRolesTable.userId eq userId.value }
            .map { it[UserRolesTable.roleName] }
            .toSet()
    }

    override suspend fun assign(userId: UserId, roleNames: Set<String>) {
        dbQuery(database) {
            UserRolesTable.deleteWhere { UserRolesTable.userId eq userId.value }
            val now = Instant.now().toDb()
            roleNames.forEach { role ->
                UserRolesTable.insert { row ->
                    row[UserRolesTable.userId] = userId.value
                    row[roleName] = role
                    row[assignedAt] = now
                }
            }
        }
    }

    /**
     * Flattened permissions in one join.
     *
     * Resolved per request by the authentication middleware; an N+1 here would be paid on
     * every single authenticated call.
     */
    override suspend fun permissionsOf(userId: UserId): Set<Permission> = dbQuery(database) {
        // The join condition is spelled out because these table definitions declare no foreign
        // keys — Flyway owns the schema, and Exposed's implicit join has nothing to infer from.
        // Left implicit it throws at runtime rather than failing to compile.
        UserRolesTable
            .join(
                otherTable = RolePermissionsTable,
                joinType = JoinType.INNER,
                onColumn = UserRolesTable.roleName,
                otherColumn = RolePermissionsTable.roleName,
            )
            .select(RolePermissionsTable.permission)
            .where { UserRolesTable.userId eq userId.value }
            .map { Permission(it[RolePermissionsTable.permission]) }
            .toSet()
    }

    private fun ResultRow.toRole(permissions: Set<Permission>) = Role(
        name = this[RolesTable.name],
        description = this[RolesTable.description],
        color = this[RolesTable.color],
        permissions = permissions,
        builtIn = this[RolesTable.builtIn],
    )
}

class ExternalIdentityRepositoryImpl(private val database: Database) : ExternalIdentityRepository {

    override suspend fun findByIssuerAndSubject(
        issuer: Issuer,
        subject: ProviderSubject,
    ): ExternalIdentity? = dbQuery(database) {
        ExternalIdentitiesTable.selectAll()
            .where {
                (ExternalIdentitiesTable.issuer eq issuer.value) and
                    (ExternalIdentitiesTable.subject eq subject.value)
            }
            .firstOrNull()?.toExternalIdentity()
    }

    override suspend fun findByUserId(userId: UserId): List<ExternalIdentity> = dbQuery(database) {
        ExternalIdentitiesTable.selectAll()
            .where { ExternalIdentitiesTable.userId eq userId.value }
            .map { it.toExternalIdentity() }
    }

    override suspend fun findByUserAndProvider(
        userId: UserId,
        provider: ProviderKey,
    ): ExternalIdentity? = dbQuery(database) {
        ExternalIdentitiesTable.selectAll()
            .where {
                (ExternalIdentitiesTable.userId eq userId.value) and
                    (ExternalIdentitiesTable.providerKey eq provider.value)
            }
            .firstOrNull()?.toExternalIdentity()
    }

    /**
     * Relies on the `(issuer, subject)` unique index rather than a prior read.
     *
     * A read-then-insert would let two concurrent link attempts both pass the check and one of
     * them attach somebody else's provider account.
     */
    override suspend fun link(identity: ExternalIdentity): ExternalIdentity = dbQuery(database) {
        try {
            ExternalIdentitiesTable.insert { row ->
                row[id] = identity.id.value
                row[userId] = identity.userId.value
                row[providerKey] = identity.providerKey.value
                row[issuer] = identity.issuer.value
                row[subject] = identity.subject.value
                row[providerEmail] = identity.providerEmail?.normalized
                row[profile] = "{}"
                row[createdAt] = identity.createdAt.toDb()
                row[lastLoginAt] = identity.lastLoginAt?.toDb()
            }
        } catch (_: org.jetbrains.exposed.v1.exceptions.ExposedSQLException) {
            throw AuthErrorException(AuthError.IdentityAlreadyLinked)
        }
        identity
    }

    override suspend fun unlink(userId: UserId, provider: ProviderKey): Boolean = dbQuery(database) {
        ExternalIdentitiesTable.deleteWhere {
            (ExternalIdentitiesTable.userId eq userId.value) and (providerKey eq provider.value)
        } > 0
    }

    override suspend fun touchLogin(id: ExternalIdentityId, at: Instant) {
        dbQuery(database) {
            ExternalIdentitiesTable.update(where = { ExternalIdentitiesTable.id eq id.value }) {
                it[lastLoginAt] = at.toDb()
            }
        }
    }

    private fun ResultRow.toExternalIdentity() = ExternalIdentity(
        id = ExternalIdentityId(this[ExternalIdentitiesTable.id]),
        userId = UserId(this[ExternalIdentitiesTable.userId]),
        providerKey = ProviderKey(this[ExternalIdentitiesTable.providerKey]),
        issuer = Issuer(this[ExternalIdentitiesTable.issuer]),
        subject = ProviderSubject(this[ExternalIdentitiesTable.subject]),
        providerEmail = this[ExternalIdentitiesTable.providerEmail]?.let { EmailAddress.restore(it, it) },
        createdAt = this[ExternalIdentitiesTable.createdAt].toInstantUtc(),
        lastLoginAt = this[ExternalIdentitiesTable.lastLoginAt]?.toInstantUtc(),
    )
}

class SessionRepositoryImpl(private val database: Database) : SessionRepository {

    override suspend fun findById(id: SessionId): Session? = dbQuery(database) {
        SessionsTable.selectAll().where { SessionsTable.id eq id.value }.firstOrNull()?.toSession()
    }

    override suspend fun findByHash(sessionHash: String): Session? = dbQuery(database) {
        SessionsTable.selectAll()
            .where { SessionsTable.sessionHash eq sessionHash }
            .firstOrNull()?.toSession()
    }

    override suspend fun listActiveForUser(userId: UserId, now: Instant): List<Session> = dbQuery(database) {
        SessionsTable.selectAll()
            .where {
                (SessionsTable.userId eq userId.value) and
                    SessionsTable.revokedAt.isNull() and
                    (SessionsTable.absoluteExpiresAt greater now.toDb()) and
                    (SessionsTable.idleExpiresAt greater now.toDb())
            }
            .orderBy(SessionsTable.lastSeenAt, SortOrder.DESC)
            .map { it.toSession() }
    }

    override suspend fun insert(session: Session, sessionHash: String): Session = dbQuery(database) {
        SessionsTable.insert { row ->
            row[id] = session.id.value
            row[userId] = session.userId.value
            row[SessionsTable.sessionHash] = sessionHash
            row[clientId] = session.clientId?.value
            row[createdAt] = session.createdAt.toDb()
            row[lastSeenAt] = session.lastSeenAt.toDb()
            row[idleExpiresAt] = session.idleExpiresAt.toDb()
            row[absoluteExpiresAt] = session.absoluteExpiresAt.toDb()
            row[revokedAt] = session.revokedAt?.toDb()
            row[authenticatedAt] = session.authenticatedAt.toDb()
            row[authenticationMethods] = session.authenticationMethods.map { it.name }.toSet().toCsv()
            row[ipHash] = session.ipHash
            row[userAgentHash] = session.userAgentHash
            row[deviceLabel] = session.deviceLabel
        }
        session
    }

    override suspend fun touch(id: SessionId, now: Instant, idleExpiresAt: Instant) {
        dbQuery(database) {
            SessionsTable.update(where = { SessionsTable.id eq id.value }) { row ->
                row[lastSeenAt] = now.toDb()
                row[SessionsTable.idleExpiresAt] = idleExpiresAt.toDb()
            }
        }
    }

    override suspend fun revoke(id: SessionId, at: Instant, reason: SessionRevocationReason): Boolean =
        dbQuery(database) {
            // Only revoke rows that are still live, so a second logout is a no-op rather than
            // an overwrite of the original revocation time.
            SessionsTable.update(
                where = { (SessionsTable.id eq id.value) and SessionsTable.revokedAt.isNull() },
            ) { it[revokedAt] = at.toDb() } > 0
        }

    override suspend fun revokeAllForUser(
        userId: UserId,
        at: Instant,
        reason: SessionRevocationReason,
        except: SessionId?,
    ): Int = dbQuery(database) {
        SessionsTable.update(
            where = {
                var op = (SessionsTable.userId eq userId.value) and SessionsTable.revokedAt.isNull()
                if (except != null) op = op and (SessionsTable.id neq except.value)
                op
            },
        ) { it[revokedAt] = at.toDb() }
    }

    override suspend fun deleteExpired(before: Instant): Int = dbQuery(database) {
        SessionsTable.deleteWhere { absoluteExpiresAt less before.toDb() }
    }

    private fun ResultRow.toSession() = Session(
        id = SessionId(this[SessionsTable.id]),
        userId = UserId(this[SessionsTable.userId]),
        clientId = this[SessionsTable.clientId]?.let { dev.kamiql.helium.domain.common.ClientId(it) },
        createdAt = this[SessionsTable.createdAt].toInstantUtc(),
        lastSeenAt = this[SessionsTable.lastSeenAt].toInstantUtc(),
        idleExpiresAt = this[SessionsTable.idleExpiresAt].toInstantUtc(),
        absoluteExpiresAt = this[SessionsTable.absoluteExpiresAt].toInstantUtc(),
        revokedAt = this[SessionsTable.revokedAt]?.toInstantUtc(),
        authenticatedAt = this[SessionsTable.authenticatedAt].toInstantUtc(),
        authenticationMethods = this[SessionsTable.authenticationMethods].fromCsv()
            .mapNotNull { name -> runCatching { AuthenticationMethod.valueOf(name) }.getOrNull() }
            .toSet(),
        ipHash = this[SessionsTable.ipHash],
        userAgentHash = this[SessionsTable.userAgentHash],
        deviceLabel = this[SessionsTable.deviceLabel],
    )
}
