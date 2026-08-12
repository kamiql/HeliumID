package dev.kamiql.helium.persistence.repository

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.RecoveryCodeId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.VerificationTokenId
import dev.kamiql.helium.domain.event.VerificationPurpose
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.RecoveryCode
import dev.kamiql.helium.domain.mfa.TotpAlgorithm
import dev.kamiql.helium.domain.mfa.TotpFactor
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.StoredVerificationToken
import dev.kamiql.helium.domain.repository.VerificationTokenRepository
import dev.kamiql.helium.persistence.MfaFactorsTable
import dev.kamiql.helium.persistence.RecoveryCodesTable
import dev.kamiql.helium.persistence.TotpFactorsTable
import dev.kamiql.helium.persistence.VerificationTokensTable
import dev.kamiql.helium.persistence.dbQuery
import dev.kamiql.helium.persistence.toDb
import dev.kamiql.helium.persistence.toInstantUtc
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import java.time.Instant

class MfaRepositoryImpl(private val database: Database) : MfaRepository {

    override suspend fun listFactors(userId: UserId): List<MfaFactor> = dbQuery(database) {
        MfaFactorsTable.selectAll()
            .where { MfaFactorsTable.userId eq userId.value }
            .map { it.toFactor() }
    }

    override suspend fun findFactor(id: MfaFactorId): MfaFactor? = dbQuery(database) {
        MfaFactorsTable.selectAll().where { MfaFactorsTable.id eq id.value }.firstOrNull()?.toFactor()
    }

    override suspend fun findActiveFactorOfType(userId: UserId, type: MfaType): MfaFactor? = dbQuery(database) {
        MfaFactorsTable.selectAll()
            .where {
                (MfaFactorsTable.userId eq userId.value) and
                    (MfaFactorsTable.type eq type.name) and
                    (MfaFactorsTable.status eq MfaFactorStatus.ACTIVE.name)
            }
            .firstOrNull()?.toFactor()
    }

    override suspend fun insertFactor(factor: MfaFactor): MfaFactor = dbQuery(database) {
        MfaFactorsTable.insert { row ->
            row[id] = factor.id.value
            row[userId] = factor.userId.value
            row[type] = factor.type.name
            row[label] = factor.label
            row[status] = factor.status.name
            row[createdAt] = factor.createdAt.toDb()
            row[lastUsedAt] = factor.lastUsedAt?.toDb()
        }
        factor
    }

    /** Only a PENDING factor can become ACTIVE, so a revoked factor cannot be resurrected. */
    override suspend fun activateFactor(id: MfaFactorId, at: Instant) {
        dbQuery(database) {
            MfaFactorsTable.update(
                where = {
                    (MfaFactorsTable.id eq id.value) and
                        (MfaFactorsTable.status eq MfaFactorStatus.PENDING.name)
                },
            ) { row ->
                row[status] = MfaFactorStatus.ACTIVE.name
                row[lastUsedAt] = at.toDb()
            }
        }
    }

    override suspend fun revokeFactor(id: MfaFactorId, at: Instant) {
        dbQuery(database) {
            MfaFactorsTable.update(where = { MfaFactorsTable.id eq id.value }) { row ->
                row[status] = MfaFactorStatus.REVOKED.name
            }
        }
    }

    override suspend fun touchFactor(id: MfaFactorId, at: Instant) {
        dbQuery(database) {
            MfaFactorsTable.update(where = { MfaFactorsTable.id eq id.value }) { row ->
                row[lastUsedAt] = at.toDb()
            }
        }
    }

    override suspend fun findTotp(factorId: MfaFactorId): TotpFactor? = dbQuery(database) {
        TotpFactorsTable.selectAll()
            .where { TotpFactorsTable.factorId eq factorId.value }
            .firstOrNull()
            ?.let { row ->
                TotpFactor(
                    factorId = factorId,
                    encryptedSecret = row[TotpFactorsTable.encryptedSecret].toByteArray(),
                    secretKeyVersion = row[TotpFactorsTable.secretKeyVersion],
                    algorithm = TotpAlgorithm.valueOf(row[TotpFactorsTable.algorithm]),
                    digits = row[TotpFactorsTable.digits],
                    periodSeconds = row[TotpFactorsTable.periodSeconds],
                    lastAcceptedStep = row[TotpFactorsTable.lastAcceptedStep],
                    createdAt = row[TotpFactorsTable.createdAt].toInstantUtc(),
                )
            }
    }

    override suspend fun insertTotp(factor: TotpFactor) {
        dbQuery(database) {
            TotpFactorsTable.insert { row ->
                row[factorId] = factor.factorId.value
                row[encryptedSecret] = String(factor.encryptedSecret)
                row[secretKeyVersion] = factor.secretKeyVersion
                row[algorithm] = factor.algorithm.name
                row[digits] = factor.digits
                row[periodSeconds] = factor.periodSeconds
                row[lastAcceptedStep] = factor.lastAcceptedStep
                row[createdAt] = factor.createdAt.toDb()
            }
        }
    }

    /**
     * Single conditional UPDATE, so the "was this step already used" check and the write cannot
     * be interleaved by a concurrent request presenting the same code.
     */
    override suspend fun tryAdvanceTotpStep(factorId: MfaFactorId, step: Long): Boolean = dbQuery(database) {
        TotpFactorsTable.update(
            where = {
                (TotpFactorsTable.factorId eq factorId.value) and
                    (
                        TotpFactorsTable.lastAcceptedStep.isNull() or
                            (TotpFactorsTable.lastAcceptedStep less step)
                        )
            },
        ) { it[lastAcceptedStep] = step } > 0
    }

    /** Regenerating replaces the whole set: leftover old codes would silently stay valid. */
    override suspend fun replaceRecoveryCodes(userId: UserId, codes: List<RecoveryCode>) {
        dbQuery(database) {
            RecoveryCodesTable.deleteWhere { RecoveryCodesTable.userId eq userId.value }
            codes.forEach { code ->
                RecoveryCodesTable.insert { row ->
                    row[id] = code.id.value
                    row[RecoveryCodesTable.userId] = userId.value
                    row[codeHash] = code.codeHash
                    row[usedAt] = code.usedAt?.toDb()
                    row[createdAt] = code.createdAt.toDb()
                }
            }
        }
    }

    override suspend fun listRecoveryCodes(userId: UserId): List<RecoveryCode> = dbQuery(database) {
        RecoveryCodesTable.selectAll()
            .where { RecoveryCodesTable.userId eq userId.value }
            .map { row ->
                RecoveryCode(
                    id = RecoveryCodeId(row[RecoveryCodesTable.id]),
                    userId = userId,
                    codeHash = row[RecoveryCodesTable.codeHash],
                    usedAt = row[RecoveryCodesTable.usedAt]?.toInstantUtc(),
                    createdAt = row[RecoveryCodesTable.createdAt].toInstantUtc(),
                )
            }
    }

    override suspend fun consumeRecoveryCode(userId: UserId, codeHash: String, at: Instant): Boolean =
        dbQuery(database) {
            RecoveryCodesTable.update(
                where = {
                    (RecoveryCodesTable.userId eq userId.value) and
                        (RecoveryCodesTable.codeHash eq codeHash) and
                        RecoveryCodesTable.usedAt.isNull()
                },
            ) { it[usedAt] = at.toDb() } > 0
        }

    override suspend fun countUnusedRecoveryCodes(userId: UserId): Int = dbQuery(database) {
        RecoveryCodesTable.selectAll()
            .where { (RecoveryCodesTable.userId eq userId.value) and RecoveryCodesTable.usedAt.isNull() }
            .count()
            .toInt()
    }

    private fun ResultRow.toFactor() = MfaFactor(
        id = MfaFactorId(this[MfaFactorsTable.id]),
        userId = UserId(this[MfaFactorsTable.userId]),
        type = MfaType.valueOf(this[MfaFactorsTable.type]),
        label = this[MfaFactorsTable.label],
        status = MfaFactorStatus.valueOf(this[MfaFactorsTable.status]),
        createdAt = this[MfaFactorsTable.createdAt].toInstantUtc(),
        lastUsedAt = this[MfaFactorsTable.lastUsedAt]?.toInstantUtc(),
    )
}

class VerificationTokenRepositoryImpl(private val database: Database) : VerificationTokenRepository {

    override suspend fun insert(token: StoredVerificationToken) {
        dbQuery(database) {
            VerificationTokensTable.insert { row ->
                row[id] = token.id.value
                row[userId] = token.userId.value
                row[tokenHash] = token.tokenHash
                row[purpose] = token.purpose.name
                row[payload] = token.payload
                row[expiresAt] = token.expiresAt.toDb()
                row[usedAt] = token.usedAt?.toDb()
                row[createdAt] = token.createdAt.toDb()
            }
        }
    }

    /**
     * Always filters on purpose as well as hash, so a token minted for email verification can
     * never be redeemed as a password reset even if an attacker learns its value.
     */
    override suspend fun findByHash(
        tokenHash: String,
        purpose: VerificationPurpose,
    ): StoredVerificationToken? = dbQuery(database) {
        VerificationTokensTable.selectAll()
            .where {
                (VerificationTokensTable.tokenHash eq tokenHash) and
                    (VerificationTokensTable.purpose eq purpose.name)
            }
            .firstOrNull()?.toToken()
    }

    override suspend fun consume(tokenHash: String, purpose: VerificationPurpose, at: Instant): Boolean =
        dbQuery(database) {
            VerificationTokensTable.update(
                where = {
                    (VerificationTokensTable.tokenHash eq tokenHash) and
                        (VerificationTokensTable.purpose eq purpose.name) and
                        VerificationTokensTable.usedAt.isNull() and
                        (VerificationTokensTable.expiresAt greater at.toDb())
                },
            ) { it[usedAt] = at.toDb() } > 0
        }

    override suspend fun invalidateAllForUser(
        userId: UserId,
        purpose: VerificationPurpose,
        at: Instant,
    ): Int = dbQuery(database) {
        VerificationTokensTable.update(
            where = {
                (VerificationTokensTable.userId eq userId.value) and
                    (VerificationTokensTable.purpose eq purpose.name) and
                    VerificationTokensTable.usedAt.isNull()
            },
        ) { it[usedAt] = at.toDb() }
    }

    override suspend fun deleteExpired(before: Instant): Int = dbQuery(database) {
        VerificationTokensTable.deleteWhere { expiresAt less before.toDb() }
    }

    private fun ResultRow.toToken() = StoredVerificationToken(
        id = VerificationTokenId(this[VerificationTokensTable.id]),
        userId = UserId(this[VerificationTokensTable.userId]),
        tokenHash = this[VerificationTokensTable.tokenHash],
        purpose = VerificationPurpose.valueOf(this[VerificationTokensTable.purpose]),
        payload = this[VerificationTokensTable.payload],
        expiresAt = this[VerificationTokensTable.expiresAt].toInstantUtc(),
        usedAt = this[VerificationTokensTable.usedAt]?.toInstantUtc(),
        createdAt = this[VerificationTokensTable.createdAt].toInstantUtc(),
    )
}
