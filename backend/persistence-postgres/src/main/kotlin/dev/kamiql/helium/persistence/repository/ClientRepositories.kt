package dev.kamiql.helium.persistence.repository

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.Consent
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.ConsentId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.repository.ClientRepository
import dev.kamiql.helium.domain.repository.ConsentRepository
import dev.kamiql.helium.domain.repository.Page
import dev.kamiql.helium.persistence.ConsentsTable
import dev.kamiql.helium.persistence.OAuthClientScopesTable
import dev.kamiql.helium.persistence.OAuthClientsTable
import dev.kamiql.helium.persistence.OAuthRedirectUrisTable
import dev.kamiql.helium.persistence.OAuthScopesTable
import dev.kamiql.helium.persistence.dbQuery
import dev.kamiql.helium.persistence.toDb
import dev.kamiql.helium.persistence.toInstantUtc
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import org.jetbrains.exposed.v1.jdbc.upsert
import java.time.Instant

class ClientRepositoryImpl(private val database: Database) : ClientRepository {

    override suspend fun findById(clientId: ClientId): OAuthClient? = dbQuery(database) {
        val row = OAuthClientsTable.selectAll()
            .where { OAuthClientsTable.clientId eq clientId.value }
            .firstOrNull() ?: return@dbQuery null
        row.toClient(redirectUrisOf(clientId.value), scopesOf(clientId.value))
    }

    override suspend fun list(limit: Int, offset: Long): Page<OAuthClient> = dbQuery(database) {
        val total = OAuthClientsTable.selectAll().count()
        val rows = OAuthClientsTable.selectAll()
            .orderBy(OAuthClientsTable.createdAt, SortOrder.DESC)
            .limit(limit)
            .offset(offset)
            .toList()

        // Two batched lookups instead of two queries per client.
        val ids = rows.map { it[OAuthClientsTable.clientId] }
        val redirects = if (ids.isEmpty()) emptyMap() else {
            OAuthRedirectUrisTable.selectAll()
                .where { OAuthRedirectUrisTable.clientId inList ids }
                .groupBy({ it[OAuthRedirectUrisTable.clientId] }) { it[OAuthRedirectUrisTable.redirectUri] }
        }
        val scopes = if (ids.isEmpty()) emptyMap() else {
            OAuthClientScopesTable.selectAll()
                .where { OAuthClientScopesTable.clientId inList ids }
                .groupBy({ it[OAuthClientScopesTable.clientId] }) { it[OAuthClientScopesTable.scope] }
        }

        Page(
            items = rows.map { row ->
                val id = row[OAuthClientsTable.clientId]
                row.toClient(redirects[id].orEmpty().toSet(), scopes[id].orEmpty().toSet())
            },
            total = total,
            limit = limit,
            offset = offset,
        )
    }

    override suspend fun insert(client: OAuthClient): OAuthClient = dbQuery(database) {
        OAuthClientsTable.insert { row ->
            row[clientId] = client.clientId.value
            row[name] = client.name
            row[type] = client.type.name
            row[secretHash] = client.secretHash
            row[secretRotatedAt] = client.secretRotatedAt?.toDb()
            row[skipConsent] = client.skipConsent
            row[audiences] = client.audiences.toCsv()
            row[grantTypes] = client.allowedGrantTypes.map { it.wireValue }.toSet().toCsv()
            row[enabled] = client.enabled
            row[createdAt] = client.createdAt.toDb()
            row[updatedAt] = client.updatedAt.toDb()
        }
        writeRedirectUris(client)
        writeScopes(client)
        client
    }

    override suspend fun update(client: OAuthClient): OAuthClient = dbQuery(database) {
        OAuthClientsTable.update(where = { OAuthClientsTable.clientId eq client.clientId.value }) { row ->
            row[name] = client.name
            row[type] = client.type.name
            row[skipConsent] = client.skipConsent
            row[audiences] = client.audiences.toCsv()
            row[grantTypes] = client.allowedGrantTypes.map { it.wireValue }.toSet().toCsv()
            row[enabled] = client.enabled
            row[updatedAt] = client.updatedAt.toDb()
        }
        // Replace rather than merge: removing a redirect URI must actually remove it.
        OAuthRedirectUrisTable.deleteWhere { clientId eq client.clientId.value }
        OAuthClientScopesTable.deleteWhere { clientId eq client.clientId.value }
        writeRedirectUris(client)
        writeScopes(client)
        client
    }

    override suspend fun updateSecret(clientId: ClientId, secretHash: String, at: Instant) {
        dbQuery(database) {
            OAuthClientsTable.update(where = { OAuthClientsTable.clientId eq clientId.value }) { row ->
                row[OAuthClientsTable.secretHash] = secretHash
                row[secretRotatedAt] = at.toDb()
                row[updatedAt] = at.toDb()
            }
        }
    }

    override suspend fun delete(clientId: ClientId): Boolean = dbQuery(database) {
        OAuthClientsTable.deleteWhere { OAuthClientsTable.clientId eq clientId.value } > 0
    }

    override suspend fun listScopes(): List<Scope> = dbQuery(database) {
        OAuthScopesTable.selectAll().map { row ->
            Scope(
                name = row[OAuthScopesTable.name],
                description = row[OAuthScopesTable.description],
                implicit = row[OAuthScopesTable.implicit],
            )
        }
    }

    private fun writeRedirectUris(client: OAuthClient) {
        client.redirectUris.forEach { uri ->
            OAuthRedirectUrisTable.insert { row ->
                row[clientId] = client.clientId.value
                row[redirectUri] = uri
            }
        }
    }

    private fun writeScopes(client: OAuthClient) {
        client.allowedScopes.forEach { scopeName ->
            OAuthClientScopesTable.insert { row ->
                row[clientId] = client.clientId.value
                row[scope] = scopeName
            }
        }
    }

    private fun redirectUrisOf(clientId: String): Set<String> =
        OAuthRedirectUrisTable.select(OAuthRedirectUrisTable.redirectUri)
            .where { OAuthRedirectUrisTable.clientId eq clientId }
            .map { it[OAuthRedirectUrisTable.redirectUri] }
            .toSet()

    private fun scopesOf(clientId: String): Set<String> =
        OAuthClientScopesTable.select(OAuthClientScopesTable.scope)
            .where { OAuthClientScopesTable.clientId eq clientId }
            .map { it[OAuthClientScopesTable.scope] }
            .toSet()

    private fun ResultRow.toClient(redirectUris: Set<String>, scopes: Set<String>) = OAuthClient(
        clientId = ClientId(this[OAuthClientsTable.clientId]),
        name = this[OAuthClientsTable.name],
        type = ClientType.valueOf(this[OAuthClientsTable.type]),
        secretHash = this[OAuthClientsTable.secretHash],
        secretRotatedAt = this[OAuthClientsTable.secretRotatedAt]?.toInstantUtc(),
        redirectUris = redirectUris,
        allowedScopes = scopes,
        allowedGrantTypes = this[OAuthClientsTable.grantTypes].fromCsv()
            .mapNotNull(GrantType::parse).toSet(),
        skipConsent = this[OAuthClientsTable.skipConsent],
        audiences = this[OAuthClientsTable.audiences].fromCsv(),
        enabled = this[OAuthClientsTable.enabled],
        createdAt = this[OAuthClientsTable.createdAt].toInstantUtc(),
        updatedAt = this[OAuthClientsTable.updatedAt].toInstantUtc(),
    )
}

class ConsentRepositoryImpl(private val database: Database) : ConsentRepository {

    override suspend fun find(userId: UserId, clientId: ClientId): Consent? = dbQuery(database) {
        ConsentsTable.selectAll()
            .where { (ConsentsTable.userId eq userId.value) and (ConsentsTable.clientId eq clientId.value) }
            .firstOrNull()?.toConsent()
    }

    /**
     * Upsert on `(user, client)`.
     *
     * Re-granting widens the stored set to whatever the user just approved; it never silently
     * merges an older, broader grant back in.
     */
    override suspend fun grant(consent: Consent): Consent = dbQuery(database) {
        val existing = ConsentsTable.selectAll()
            .where {
                (ConsentsTable.userId eq consent.userId.value) and
                    (ConsentsTable.clientId eq consent.clientId.value)
            }
            .firstOrNull()

        if (existing == null) {
            ConsentsTable.insert { row ->
                row[id] = consent.id.value
                row[userId] = consent.userId.value
                row[clientId] = consent.clientId.value
                row[grantedScopes] = consent.grantedScopes.toCsv()
                row[grantedAt] = consent.grantedAt.toDb()
                row[revokedAt] = null
            }
            consent
        } else {
            ConsentsTable.update(where = { ConsentsTable.id eq existing[ConsentsTable.id] }) { row ->
                row[grantedScopes] = consent.grantedScopes.toCsv()
                row[grantedAt] = consent.grantedAt.toDb()
                row[revokedAt] = null
            }
            consent.copy(id = ConsentId(existing[ConsentsTable.id]))
        }
    }

    override suspend fun revoke(userId: UserId, clientId: ClientId, at: Instant): Boolean = dbQuery(database) {
        ConsentsTable.update(
            where = {
                (ConsentsTable.userId eq userId.value) and
                    (ConsentsTable.clientId eq clientId.value) and
                    ConsentsTable.revokedAt.isNull()
            },
        ) { it[revokedAt] = at.toDb() } > 0
    }

    override suspend fun listForUser(userId: UserId): List<Consent> = dbQuery(database) {
        ConsentsTable.selectAll()
            .where { (ConsentsTable.userId eq userId.value) and ConsentsTable.revokedAt.isNull() }
            .map { it.toConsent() }
    }

    private fun ResultRow.toConsent() = Consent(
        id = ConsentId(this[ConsentsTable.id]),
        userId = UserId(this[ConsentsTable.userId]),
        clientId = ClientId(this[ConsentsTable.clientId]),
        grantedScopes = this[ConsentsTable.grantedScopes].fromCsv(),
        grantedAt = this[ConsentsTable.grantedAt].toInstantUtc(),
        revokedAt = this[ConsentsTable.revokedAt]?.toInstantUtc(),
    )
}
