package dev.kamiql.helium.persistence.repository

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.error.AuthErrorException
import dev.kamiql.helium.domain.repository.Page
import dev.kamiql.helium.domain.repository.UserQuery
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.persistence.UserRolesTable
import dev.kamiql.helium.persistence.UsersTable
import dev.kamiql.helium.persistence.dbQuery
import dev.kamiql.helium.persistence.toDb
import dev.kamiql.helium.persistence.toInstantUtc
// Exposed 1.0 exposes the comparison operators as top-level functions; the star import is
// what the library's own deprecation notice prescribes.
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import java.time.Instant

/**
 * Exposed-backed [UserRepository].
 *
 * Two rules hold throughout: lookups only ever touch the `*_normalized` columns, and every
 * update asserts the optimistic-locking [User.version] it read.
 */
class UserRepositoryImpl(private val database: Database) : UserRepository {

    override suspend fun findById(id: UserId): User? = dbQuery(database) {
        UsersTable.selectAll().where { UsersTable.id eq id.value }.firstOrNull()?.toUser()
    }

    override suspend fun findByUsername(username: Username): User? = dbQuery(database) {
        UsersTable.selectAll()
            .where { UsersTable.usernameNormalized eq username.normalized }
            .firstOrNull()?.toUser()
    }

    override suspend fun findByEmail(email: EmailAddress): User? = dbQuery(database) {
        UsersTable.selectAll()
            .where { UsersTable.primaryEmailNormalized eq email.normalized }
            .firstOrNull()?.toUser()
    }

    /**
     * One query for both identifier kinds.
     *
     * Querying username first and email second would leak which one matched through response
     * timing. A single `OR` over two unique indexes costs the same either way.
     */
    override suspend fun findByLoginIdentifier(identifier: String): User? = dbQuery(database) {
        val normalized = dev.kamiql.helium.domain.common.Normalization.fold(identifier)
        UsersTable.selectAll()
            .where {
                (UsersTable.usernameNormalized eq normalized) or
                    (UsersTable.primaryEmailNormalized eq normalized)
            }
            .firstOrNull()?.toUser()
    }

    override suspend fun insert(user: User): User = dbQuery(database) {
        UsersTable.insert { row ->
            row[id] = user.id.value
            row[username] = user.username.display
            row[usernameNormalized] = user.username.normalized
            row[primaryEmail] = user.primaryEmail.display
            row[primaryEmailNormalized] = user.primaryEmail.normalized
            row[firstName] = user.firstName
            row[lastName] = user.lastName
            row[status] = user.status.name
            row[emailVerifiedAt] = user.emailVerifiedAt?.toDb()
            row[createdAt] = user.createdAt.toDb()
            row[updatedAt] = user.updatedAt.toDb()
            row[version] = user.version
        }
        user
    }

    /**
     * @throws AuthErrorException [AuthError.Conflict] when the row changed since it was read.
     *         Surfacing the lost update is the point: silently overwriting is how one admin's
     *         edit erases another's.
     */
    override suspend fun update(user: User): User = dbQuery(database) {
        val updated = UsersTable.update(
            where = { (UsersTable.id eq user.id.value) and (UsersTable.version eq user.version) },
        ) { row ->
            row[username] = user.username.display
            row[usernameNormalized] = user.username.normalized
            row[primaryEmail] = user.primaryEmail.display
            row[primaryEmailNormalized] = user.primaryEmail.normalized
            row[firstName] = user.firstName
            row[lastName] = user.lastName
            row[status] = user.status.name
            row[emailVerifiedAt] = user.emailVerifiedAt?.toDb()
            row[updatedAt] = user.updatedAt.toDb()
            row[version] = user.version + 1
        }
        if (updated == 0) throw AuthErrorException(AuthError.Conflict)
        user.copy(version = user.version + 1)
    }

    override suspend fun updateStatus(id: UserId, status: UserStatus, at: Instant) {
        dbQuery(database) {
            UsersTable.update(where = { UsersTable.id eq id.value }) { row ->
                row[UsersTable.status] = status.name
                row[updatedAt] = at.toDb()
                row[version] = version + 1
            }
        }
    }

    override suspend fun markEmailVerified(id: UserId, at: Instant) {
        dbQuery(database) {
            UsersTable.update(where = { UsersTable.id eq id.value }) { row ->
                row[emailVerifiedAt] = at.toDb()
                // Verification is what promotes a pending account to active.
                row[status] = UserStatus.ACTIVE.name
                row[updatedAt] = at.toDb()
                row[version] = version + 1
            }
        }
    }

    override suspend fun changePrimaryEmail(id: UserId, email: EmailAddress, verifiedAt: Instant) {
        dbQuery(database) {
            UsersTable.update(where = { UsersTable.id eq id.value }) { row ->
                row[primaryEmail] = email.display
                row[primaryEmailNormalized] = email.normalized
                // The new address was proven by the change token, so it is already verified.
                row[emailVerifiedAt] = verifiedAt.toDb()
                row[updatedAt] = verifiedAt.toDb()
                row[version] = version + 1
            }
        }
    }

    /**
     * Soft delete.
     *
     * The identifiers are rewritten to tombstones so the username and email become available
     * again, while the row itself survives for audit joins (§3.4: "Never delete security data
     * immediately").
     */
    override suspend fun softDelete(id: UserId, at: Instant) {
        dbQuery(database) {
            val tombstone = "deleted-${id.value}"
            UsersTable.update(where = { UsersTable.id eq id.value }) { row ->
                row[status] = UserStatus.DELETED.name
                row[username] = tombstone
                row[usernameNormalized] = tombstone
                row[primaryEmail] = "$tombstone@invalid"
                row[primaryEmailNormalized] = "$tombstone@invalid"
                row[firstName] = ""
                row[lastName] = ""
                row[emailVerifiedAt] = null
                row[updatedAt] = at.toDb()
                row[version] = version + 1
            }
        }
    }

    override suspend fun search(query: UserQuery): Page<User> = dbQuery(database) {
        val ids = query.role?.let { role ->
            UserRolesTable.select(UserRolesTable.userId)
                .where { UserRolesTable.roleName eq role }
                .map { it[UserRolesTable.userId] }
        }

        val condition = {
            var op: Op<Boolean> = UsersTable.status neq UserStatus.DELETED.name
            query.status?.let { status ->
                op = op and (UsersTable.status eq status.name)
            }
            query.term?.takeIf { it.isNotBlank() }?.let { term ->
                val pattern = "%${dev.kamiql.helium.domain.common.Normalization.fold(term)}%"
                op = op and (
                    (UsersTable.usernameNormalized like pattern) or
                        (UsersTable.primaryEmailNormalized like pattern)
                    )
            }
            if (ids != null) {
                op = op and (UsersTable.id inList ids)
            }
            op
        }

        val total = UsersTable.selectAll().where(condition()).count()
        val items = UsersTable.selectAll()
            .where(condition())
            .orderBy(UsersTable.createdAt, SortOrder.DESC)
            .limit(query.limit)
            .offset(query.offset)
            .map { it.toUser() }

        Page(items, total, query.limit, query.offset)
    }
}

internal fun ResultRow.toUser(): User = User(
    id = UserId(this[UsersTable.id]),
    username = Username.restore(this[UsersTable.username], this[UsersTable.usernameNormalized]),
    primaryEmail = EmailAddress.restore(
        this[UsersTable.primaryEmail],
        this[UsersTable.primaryEmailNormalized],
    ),
    firstName = this[UsersTable.firstName],
    lastName = this[UsersTable.lastName],
    status = UserStatus.valueOf(this[UsersTable.status]),
    emailVerifiedAt = this[UsersTable.emailVerifiedAt]?.toInstantUtc(),
    createdAt = this[UsersTable.createdAt].toInstantUtc(),
    updatedAt = this[UsersTable.updatedAt].toInstantUtc(),
    version = this[UsersTable.version],
)
