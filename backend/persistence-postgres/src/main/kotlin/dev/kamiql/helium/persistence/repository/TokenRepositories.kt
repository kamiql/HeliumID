package dev.kamiql.helium.persistence.repository

import dev.kamiql.helium.domain.common.AuthorizationCodeId
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.RefreshTokenFamilyId
import dev.kamiql.helium.domain.common.RefreshTokenId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.SigningKeyId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.repository.AuthorizationCodeRepository
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.domain.repository.RevokedTokenRepository
import dev.kamiql.helium.domain.repository.SigningKeyRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.token.AuthorizationCode
import dev.kamiql.helium.domain.token.CodeChallengeMethod
import dev.kamiql.helium.domain.token.RefreshToken
import dev.kamiql.helium.domain.token.RefreshTokenFamily
import dev.kamiql.helium.domain.token.SigningAlgorithm
import dev.kamiql.helium.domain.token.SigningKey
import dev.kamiql.helium.domain.token.SigningKeyStatus
import dev.kamiql.helium.persistence.AuthorizationCodesTable
import dev.kamiql.helium.persistence.RefreshTokenFamiliesTable
import dev.kamiql.helium.persistence.RefreshTokensTable
import dev.kamiql.helium.persistence.RevokedAccessTokensTable
import dev.kamiql.helium.persistence.SigningKeysTable
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

class RefreshTokenRepositoryImpl(private val database: Database) : RefreshTokenRepository {

    override suspend fun createFamily(family: RefreshTokenFamily): RefreshTokenFamily = dbQuery(database) {
        RefreshTokenFamiliesTable.insert { row ->
            row[id] = family.id.value
            row[userId] = family.userId.value
            row[clientId] = family.clientId.value
            row[sessionId] = family.sessionId?.value
            row[scopes] = family.scopes.toCsv()
            row[authenticationMethods] = family.authenticationMethods.map { it.name }.toSet().toCsv()
            row[createdAt] = family.createdAt.toDb()
            row[absoluteExpiresAt] = family.absoluteExpiresAt.toDb()
            row[revokedAt] = family.revokedAt?.toDb()
            row[reuseDetectedAt] = family.reuseDetectedAt?.toDb()
        }
        family
    }

    override suspend fun findFamily(id: RefreshTokenFamilyId): RefreshTokenFamily? = dbQuery(database) {
        RefreshTokenFamiliesTable.selectAll()
            .where { RefreshTokenFamiliesTable.id eq id.value }
            .firstOrNull()?.toFamily()
    }

    override suspend fun insertToken(token: RefreshToken): RefreshToken = dbQuery(database) {
        RefreshTokensTable.insert { row ->
            row[id] = token.id.value
            row[familyId] = token.familyId.value
            row[tokenHash] = token.tokenHash
            row[issuedAt] = token.issuedAt.toDb()
            row[expiresAt] = token.expiresAt.toDb()
            row[usedAt] = token.usedAt?.toDb()
            row[revokedAt] = token.revokedAt?.toDb()
            row[replacedByTokenId] = token.replacedByTokenId?.value
        }
        token
    }

    override suspend fun findByHash(tokenHash: String): RefreshToken? = dbQuery(database) {
        RefreshTokensTable.selectAll()
            .where { RefreshTokensTable.tokenHash eq tokenHash }
            .firstOrNull()?.toToken()
    }

    /**
     * The heart of rotation.
     *
     * A single conditional UPDATE guarded on `used_at IS NULL`: exactly one of two concurrent
     * refreshes with the same token can win, and the loser gets `false`, which the flow treats
     * as reuse. A read-then-write here would hand both callers a valid token pair.
     */
    override suspend fun markUsed(tokenId: RefreshTokenId, at: Instant, replacedBy: RefreshTokenId): Boolean =
        dbQuery(database) {
            RefreshTokensTable.update(
                where = {
                    (RefreshTokensTable.id eq tokenId.value) and
                        RefreshTokensTable.usedAt.isNull() and
                        RefreshTokensTable.revokedAt.isNull()
                },
            ) { row ->
                row[usedAt] = at.toDb()
                row[replacedByTokenId] = replacedBy.value
            } > 0
        }

    override suspend fun revokeFamily(
        familyId: RefreshTokenFamilyId,
        at: Instant,
        reuseDetected: Boolean,
    ): Int = dbQuery(database) {
        RefreshTokenFamiliesTable.update(where = { RefreshTokenFamiliesTable.id eq familyId.value }) { row ->
            row[revokedAt] = at.toDb()
            if (reuseDetected) row[reuseDetectedAt] = at.toDb()
        }
        RefreshTokensTable.update(
            where = { (RefreshTokensTable.familyId eq familyId.value) and RefreshTokensTable.revokedAt.isNull() },
        ) { it[revokedAt] = at.toDb() }
    }

    override suspend fun revokeFamiliesForUser(userId: UserId, at: Instant): Int = dbQuery(database) {
        val families = RefreshTokenFamiliesTable.select(RefreshTokenFamiliesTable.id)
            .where {
                (RefreshTokenFamiliesTable.userId eq userId.value) and
                    RefreshTokenFamiliesTable.revokedAt.isNull()
            }
            .map { it[RefreshTokenFamiliesTable.id] }
        revokeFamilies(families, at)
    }

    override suspend fun revokeFamiliesForSession(sessionId: SessionId, at: Instant): Int = dbQuery(database) {
        val families = RefreshTokenFamiliesTable.select(RefreshTokenFamiliesTable.id)
            .where {
                (RefreshTokenFamiliesTable.sessionId eq sessionId.value) and
                    RefreshTokenFamiliesTable.revokedAt.isNull()
            }
            .map { it[RefreshTokenFamiliesTable.id] }
        revokeFamilies(families, at)
    }

    override suspend fun listActiveFamiliesForUser(
        userId: UserId,
        now: Instant,
    ): List<RefreshTokenFamily> = dbQuery(database) {
        RefreshTokenFamiliesTable.selectAll()
            .where {
                (RefreshTokenFamiliesTable.userId eq userId.value) and
                    RefreshTokenFamiliesTable.revokedAt.isNull() and
                    RefreshTokenFamiliesTable.reuseDetectedAt.isNull() and
                    (RefreshTokenFamiliesTable.absoluteExpiresAt greater now.toDb())
            }
            .orderBy(RefreshTokenFamiliesTable.createdAt, SortOrder.DESC)
            .map { it.toFamily() }
    }

    override suspend fun revokeFamiliesForUserAndClient(
        userId: UserId,
        clientId: ClientId,
        at: Instant,
    ): Int = dbQuery(database) {
        val families = RefreshTokenFamiliesTable.select(RefreshTokenFamiliesTable.id)
            .where {
                (RefreshTokenFamiliesTable.userId eq userId.value) and
                    (RefreshTokenFamiliesTable.clientId eq clientId.value) and
                    RefreshTokenFamiliesTable.revokedAt.isNull()
            }
            .map { it[RefreshTokenFamiliesTable.id] }
        revokeFamilies(families, at)
    }

    private fun revokeFamilies(familyIds: List<java.util.UUID>, at: Instant): Int {
        if (familyIds.isEmpty()) return 0
        RefreshTokenFamiliesTable.update(where = { RefreshTokenFamiliesTable.id inList familyIds }) {
            it[revokedAt] = at.toDb()
        }
        RefreshTokensTable.update(
            where = { (RefreshTokensTable.familyId inList familyIds) and RefreshTokensTable.revokedAt.isNull() },
        ) { it[revokedAt] = at.toDb() }
        return familyIds.size
    }

    override suspend fun deleteExpired(before: Instant): Int = dbQuery(database) {
        // Families cascade to their tokens, so deleting the family is enough.
        RefreshTokenFamiliesTable.deleteWhere { absoluteExpiresAt less before.toDb() }
    }

    private fun ResultRow.toFamily() = RefreshTokenFamily(
        id = RefreshTokenFamilyId(this[RefreshTokenFamiliesTable.id]),
        userId = UserId(this[RefreshTokenFamiliesTable.userId]),
        clientId = ClientId(this[RefreshTokenFamiliesTable.clientId]),
        sessionId = this[RefreshTokenFamiliesTable.sessionId]?.let(::SessionId),
        scopes = this[RefreshTokenFamiliesTable.scopes].fromCsv(),
        authenticationMethods = this[RefreshTokenFamiliesTable.authenticationMethods].fromCsv()
            .mapNotNull { runCatching { AuthenticationMethod.valueOf(it) }.getOrNull() }.toSet(),
        createdAt = this[RefreshTokenFamiliesTable.createdAt].toInstantUtc(),
        absoluteExpiresAt = this[RefreshTokenFamiliesTable.absoluteExpiresAt].toInstantUtc(),
        revokedAt = this[RefreshTokenFamiliesTable.revokedAt]?.toInstantUtc(),
        reuseDetectedAt = this[RefreshTokenFamiliesTable.reuseDetectedAt]?.toInstantUtc(),
    )

    private fun ResultRow.toToken() = RefreshToken(
        id = RefreshTokenId(this[RefreshTokensTable.id]),
        familyId = RefreshTokenFamilyId(this[RefreshTokensTable.familyId]),
        tokenHash = this[RefreshTokensTable.tokenHash],
        issuedAt = this[RefreshTokensTable.issuedAt].toInstantUtc(),
        expiresAt = this[RefreshTokensTable.expiresAt].toInstantUtc(),
        usedAt = this[RefreshTokensTable.usedAt]?.toInstantUtc(),
        revokedAt = this[RefreshTokensTable.revokedAt]?.toInstantUtc(),
        replacedByTokenId = this[RefreshTokensTable.replacedByTokenId]?.let(::RefreshTokenId),
    )
}

class AuthorizationCodeRepositoryImpl(private val database: Database) : AuthorizationCodeRepository {

    override suspend fun insert(code: AuthorizationCode): AuthorizationCode = dbQuery(database) {
        AuthorizationCodesTable.insert { row ->
            row[id] = code.id.value
            row[codeHash] = code.codeHash
            row[clientId] = code.clientId.value
            row[userId] = code.userId.value
            row[sessionId] = code.sessionId?.value
            row[redirectUri] = code.redirectUri
            row[scopes] = code.scopes.toCsv()
            row[nonce] = code.nonce
            row[codeChallenge] = code.codeChallenge
            row[codeChallengeMethod] = code.codeChallengeMethod.name
            row[authenticationMethods] = code.authenticationMethods.map { it.name }.toSet().toCsv()
            row[authenticatedAt] = code.authenticatedAt.toDb()
            row[issuedAt] = code.issuedAt.toDb()
            row[expiresAt] = code.expiresAt.toDb()
            row[consumedAt] = code.consumedAt?.toDb()
        }
        code
    }

    override suspend fun findByHash(codeHash: String): AuthorizationCode? = dbQuery(database) {
        AuthorizationCodesTable.selectAll()
            .where { AuthorizationCodesTable.codeHash eq codeHash }
            .firstOrNull()?.toCode()
    }

    /** `false` means the code was already redeemed, which the token endpoint treats as replay. */
    override suspend fun consume(id: AuthorizationCodeId, at: Instant): Boolean = dbQuery(database) {
        AuthorizationCodesTable.update(
            where = {
                (AuthorizationCodesTable.id eq id.value) and
                    AuthorizationCodesTable.consumedAt.isNull() and
                    (AuthorizationCodesTable.expiresAt greater at.toDb())
            },
        ) { it[consumedAt] = at.toDb() } > 0
    }

    override suspend fun deleteExpired(before: Instant): Int = dbQuery(database) {
        AuthorizationCodesTable.deleteWhere { expiresAt less before.toDb() }
    }

    private fun ResultRow.toCode() = AuthorizationCode(
        id = AuthorizationCodeId(this[AuthorizationCodesTable.id]),
        codeHash = this[AuthorizationCodesTable.codeHash],
        clientId = ClientId(this[AuthorizationCodesTable.clientId]),
        userId = UserId(this[AuthorizationCodesTable.userId]),
        sessionId = this[AuthorizationCodesTable.sessionId]?.let(::SessionId),
        redirectUri = this[AuthorizationCodesTable.redirectUri],
        scopes = this[AuthorizationCodesTable.scopes].fromCsv(),
        nonce = this[AuthorizationCodesTable.nonce],
        codeChallenge = this[AuthorizationCodesTable.codeChallenge],
        codeChallengeMethod = CodeChallengeMethod.valueOf(this[AuthorizationCodesTable.codeChallengeMethod]),
        authenticationMethods = this[AuthorizationCodesTable.authenticationMethods].fromCsv()
            .mapNotNull { runCatching { AuthenticationMethod.valueOf(it) }.getOrNull() }.toSet(),
        authenticatedAt = this[AuthorizationCodesTable.authenticatedAt].toInstantUtc(),
        issuedAt = this[AuthorizationCodesTable.issuedAt].toInstantUtc(),
        expiresAt = this[AuthorizationCodesTable.expiresAt].toInstantUtc(),
        consumedAt = this[AuthorizationCodesTable.consumedAt]?.toInstantUtc(),
    )
}

class RevokedTokenRepositoryImpl(private val database: Database) : RevokedTokenRepository {

    override suspend fun revoke(tokenId: String, expiresAt: Instant, at: Instant) {
        dbQuery(database) {
            RevokedAccessTokensTable.upsert(RevokedAccessTokensTable.tokenId) { row ->
                row[RevokedAccessTokensTable.tokenId] = tokenId
                row[RevokedAccessTokensTable.expiresAt] = expiresAt.toDb()
                row[revokedAt] = at.toDb()
            }
        }
    }

    override suspend fun isRevoked(tokenId: String): Boolean = dbQuery(database) {
        RevokedAccessTokensTable.selectAll()
            .where { RevokedAccessTokensTable.tokenId eq tokenId }
            .empty()
            .not()
    }

    override suspend fun deleteExpired(before: Instant): Int = dbQuery(database) {
        RevokedAccessTokensTable.deleteWhere { expiresAt less before.toDb() }
    }
}

class SigningKeyRepositoryImpl(private val database: Database) : SigningKeyRepository {

    override suspend fun findActive(): SigningKey? = dbQuery(database) {
        SigningKeysTable.selectAll()
            .where { SigningKeysTable.status eq SigningKeyStatus.ACTIVE.name }
            .firstOrNull()?.toKey()
    }

    override suspend fun findById(id: SigningKeyId): SigningKey? = dbQuery(database) {
        SigningKeysTable.selectAll().where { SigningKeysTable.id eq id.value }.firstOrNull()?.toKey()
    }

    /** Everything a verifier should still accept: anything not yet retired. */
    override suspend fun listPublishable(): List<SigningKey> = dbQuery(database) {
        SigningKeysTable.selectAll()
            .where { SigningKeysTable.status neq SigningKeyStatus.RETIRED.name }
            .orderBy(SigningKeysTable.createdAt, SortOrder.DESC)
            .map { it.toKey() }
    }

    override suspend fun insert(key: SigningKey): SigningKey = dbQuery(database) {
        SigningKeysTable.insert { row ->
            row[id] = key.id.value
            row[algorithm] = key.algorithm.name
            row[publicJwk] = key.publicJwk
            row[encryptedPrivateKey] = key.encryptedPrivateKey
            row[status] = key.status.name
            row[createdAt] = key.createdAt.toDb()
            row[activatedAt] = key.activatedAt?.toDb()
            row[retiresAt] = key.retiresAt?.toDb()
        }
        key
    }

    /**
     * Demotes the current signer before promoting the new one.
     *
     * The partial unique index on `status = 'ACTIVE'` means getting this order wrong fails the
     * transaction rather than leaving two active keys.
     */
    override suspend fun promote(id: SigningKeyId, at: Instant) {
        dbQuery(database) {
            SigningKeysTable.update(where = { SigningKeysTable.status eq SigningKeyStatus.ACTIVE.name }) {
                it[status] = SigningKeyStatus.RETIRING.name
            }
            SigningKeysTable.update(where = { SigningKeysTable.id eq id.value }) { row ->
                row[status] = SigningKeyStatus.ACTIVE.name
                row[activatedAt] = at.toDb()
            }
        }
    }

    override suspend fun retire(id: SigningKeyId, at: Instant) {
        dbQuery(database) {
            SigningKeysTable.update(where = { SigningKeysTable.id eq id.value }) { row ->
                row[status] = SigningKeyStatus.RETIRED.name
                row[retiresAt] = at.toDb()
            }
        }
    }

    private fun ResultRow.toKey() = SigningKey(
        id = SigningKeyId(this[SigningKeysTable.id]),
        algorithm = SigningAlgorithm.valueOf(this[SigningKeysTable.algorithm]),
        publicJwk = this[SigningKeysTable.publicJwk],
        encryptedPrivateKey = this[SigningKeysTable.encryptedPrivateKey],
        status = SigningKeyStatus.valueOf(this[SigningKeysTable.status]),
        createdAt = this[SigningKeysTable.createdAt].toInstantUtc(),
        activatedAt = this[SigningKeysTable.activatedAt]?.toInstantUtc(),
        retiresAt = this[SigningKeysTable.retiresAt]?.toInstantUtc(),
    )
}
