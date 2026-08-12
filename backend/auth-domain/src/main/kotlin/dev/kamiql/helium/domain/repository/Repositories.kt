package dev.kamiql.helium.domain.repository

import dev.kamiql.helium.domain.client.Consent
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.AuthorizationCodeId
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.SigningKeyId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.credential.PasswordCredential
import dev.kamiql.helium.domain.credential.PasswordHash
import dev.kamiql.helium.domain.event.VerificationPurpose
import dev.kamiql.helium.domain.identity.ExternalIdentity
import dev.kamiql.helium.domain.identity.Issuer
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.identity.ProviderSubject
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.RecoveryCode
import dev.kamiql.helium.domain.mfa.TotpFactor
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.domain.token.AuthorizationCode
import dev.kamiql.helium.domain.token.RefreshToken
import dev.kamiql.helium.domain.token.RefreshTokenFamily
import dev.kamiql.helium.domain.token.SigningKey
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import java.time.Instant

/**
 * Repository ports.
 *
 * All of them are `suspend` and none of them expose a transaction handle: transaction scope is
 * owned by the flow engine
 * ([TransactionManager][dev.kamiql.helium.flow.port.TransactionManager]), so no individual
 * repository call can decide to commit. Implementations join the ambient transaction.
 *
 * None of these signatures mention SQL, connections or row types — CLAUDE.md keeps the domain
 * free of persistence concepts.
 */
interface UserRepository {

    suspend fun findById(id: UserId): User?

    /** Lookup by the normalized form only; callers must never pass raw input. */
    suspend fun findByUsername(username: Username): User?

    suspend fun findByEmail(email: EmailAddress): User?

    /**
     * Resolves a login identifier that may be either a username or an email address.
     *
     * One query rather than two so that "unknown user" costs the same regardless of which kind
     * of identifier was supplied.
     */
    suspend fun findByLoginIdentifier(identifier: String): User?

    suspend fun insert(user: User): User

    /**
     * @throws dev.kamiql.helium.domain.error.AuthErrorException with
     *         [dev.kamiql.helium.domain.error.AuthError.Conflict] when [User.version] no longer
     *         matches the stored row.
     */
    suspend fun update(user: User): User

    suspend fun updateStatus(id: UserId, status: UserStatus, at: Instant)

    suspend fun markEmailVerified(id: UserId, at: Instant)

    suspend fun changePrimaryEmail(id: UserId, email: EmailAddress, verifiedAt: Instant)

    /** Soft delete. Security data is retained per concept §3.4. */
    suspend fun softDelete(id: UserId, at: Instant)

    suspend fun search(query: UserQuery): Page<User>
}

/** Admin user-list filter. Free-text [term] matches the normalized username or email prefix. */
data class UserQuery(
    val term: String? = null,
    val status: UserStatus? = null,
    val role: String? = null,
    val limit: Int = 50,
    val offset: Long = 0,
)

/** A slice of results plus the total, for offset pagination in the admin UI. */
data class Page<T>(val items: List<T>, val total: Long, val limit: Int, val offset: Long)

interface PasswordCredentialRepository {
    suspend fun findByUserId(userId: UserId): PasswordCredential?
    suspend fun upsert(userId: UserId, hash: PasswordHash, at: Instant)
    suspend fun delete(userId: UserId)
}

interface ExternalIdentityRepository {

    /** The only safe lookup: the provider-asserted `(issuer, subject)` pair (concept §9.4). */
    suspend fun findByIssuerAndSubject(issuer: Issuer, subject: ProviderSubject): ExternalIdentity?

    suspend fun findByUserId(userId: UserId): List<ExternalIdentity>

    suspend fun findByUserAndProvider(userId: UserId, provider: ProviderKey): ExternalIdentity?

    /**
     * @throws dev.kamiql.helium.domain.error.AuthErrorException with
     *         [dev.kamiql.helium.domain.error.AuthError.IdentityAlreadyLinked] if the
     *         `(issuer, subject)` unique constraint is violated. Relying on the constraint
     *         rather than a prior read closes the check-then-act race.
     */
    suspend fun link(identity: ExternalIdentity): ExternalIdentity

    suspend fun unlink(userId: UserId, provider: ProviderKey): Boolean

    suspend fun touchLogin(id: dev.kamiql.helium.domain.common.ExternalIdentityId, at: Instant)
}

interface SessionRepository {
    suspend fun findById(id: SessionId): Session?
    suspend fun findByHash(sessionHash: String): Session?
    suspend fun listActiveForUser(userId: UserId, now: Instant): List<Session>
    suspend fun insert(session: Session, sessionHash: String): Session
    suspend fun touch(id: SessionId, now: Instant, idleExpiresAt: Instant)
    suspend fun revoke(id: SessionId, at: Instant, reason: SessionRevocationReason): Boolean

    /**
     * Revokes every active session for the user, optionally sparing one.
     *
     * @param except keeps the caller signed in after a password change — the alternative,
     *        logging the user out of the device they are actively using, trains people to
     *        ignore the "your password changed" mail.
     * @return number of sessions revoked.
     */
    suspend fun revokeAllForUser(
        userId: UserId,
        at: Instant,
        reason: SessionRevocationReason,
        except: SessionId? = null,
    ): Int

    /** Deletes sessions whose absolute expiry has passed. Called by the cleanup job. */
    suspend fun deleteExpired(before: Instant): Int
}

interface MfaRepository {
    suspend fun listFactors(userId: UserId): List<MfaFactor>
    suspend fun findFactor(id: MfaFactorId): MfaFactor?
    suspend fun findActiveFactorOfType(userId: UserId, type: MfaType): MfaFactor?
    suspend fun insertFactor(factor: MfaFactor): MfaFactor
    suspend fun activateFactor(id: MfaFactorId, at: Instant)
    suspend fun revokeFactor(id: MfaFactorId, at: Instant)
    suspend fun touchFactor(id: MfaFactorId, at: Instant)

    suspend fun findTotp(factorId: MfaFactorId): TotpFactor?
    suspend fun insertTotp(factor: TotpFactor)

    /**
     * Conditionally advances the replay guard.
     *
     * @return `false` when [step] is not greater than the stored value, which means this code
     *         was already accepted. Implemented as a single conditional UPDATE so two
     *         concurrent requests cannot both succeed with the same code.
     */
    suspend fun tryAdvanceTotpStep(factorId: MfaFactorId, step: Long): Boolean

    suspend fun replaceRecoveryCodes(userId: UserId, codes: List<RecoveryCode>)
    suspend fun listRecoveryCodes(userId: UserId): List<RecoveryCode>

    /** Single-use consumption; returns `false` if the code was already spent. */
    suspend fun consumeRecoveryCode(userId: UserId, codeHash: String, at: Instant): Boolean

    suspend fun countUnusedRecoveryCodes(userId: UserId): Int
}

/** One-time email verification, email change and password reset tokens. Stored hashed. */
interface VerificationTokenRepository {

    suspend fun insert(token: StoredVerificationToken)

    suspend fun findByHash(tokenHash: String, purpose: VerificationPurpose): StoredVerificationToken?

    /** Marks used. Returns `false` if it was already consumed — the replay guard. */
    suspend fun consume(tokenHash: String, purpose: VerificationPurpose, at: Instant): Boolean

    /**
     * Invalidates outstanding tokens of the same purpose for the user.
     *
     * Concept §2.6: requesting a new reset link must retire the previous one.
     */
    suspend fun invalidateAllForUser(userId: UserId, purpose: VerificationPurpose, at: Instant): Int

    suspend fun deleteExpired(before: Instant): Int
}

data class StoredVerificationToken(
    val id: dev.kamiql.helium.domain.common.VerificationTokenId,
    val userId: UserId,
    val tokenHash: String,
    val purpose: VerificationPurpose,
    /** For an email-change token, the address being claimed. */
    val payload: String?,
    val expiresAt: Instant,
    val usedAt: Instant?,
    val createdAt: Instant,
)

interface RefreshTokenRepository {
    suspend fun createFamily(family: RefreshTokenFamily): RefreshTokenFamily
    suspend fun findFamily(id: dev.kamiql.helium.domain.common.RefreshTokenFamilyId): RefreshTokenFamily?
    suspend fun insertToken(token: RefreshToken): RefreshToken
    suspend fun findByHash(tokenHash: String): RefreshToken?

    /**
     * Atomically marks the token used and records its replacement.
     *
     * @return `false` when the row was already marked used, which is exactly the reuse signal.
     *         Must be a single conditional UPDATE: doing read-then-write here would let two
     *         concurrent refreshes both succeed.
     */
    suspend fun markUsed(
        tokenId: dev.kamiql.helium.domain.common.RefreshTokenId,
        at: Instant,
        replacedBy: dev.kamiql.helium.domain.common.RefreshTokenId,
    ): Boolean

    suspend fun revokeFamily(
        familyId: dev.kamiql.helium.domain.common.RefreshTokenFamilyId,
        at: Instant,
        reuseDetected: Boolean,
    ): Int

    suspend fun revokeFamiliesForUser(userId: UserId, at: Instant): Int
    suspend fun revokeFamiliesForSession(sessionId: SessionId, at: Instant): Int
    suspend fun deleteExpired(before: Instant): Int
}

interface AuthorizationCodeRepository {
    suspend fun insert(code: AuthorizationCode): AuthorizationCode
    suspend fun findByHash(codeHash: String): AuthorizationCode?

    /** Single-use consumption; `false` means it was already redeemed (replay). */
    suspend fun consume(id: AuthorizationCodeId, at: Instant): Boolean

    suspend fun deleteExpired(before: Instant): Int
}

interface ClientRepository {
    suspend fun findById(clientId: ClientId): OAuthClient?
    suspend fun list(limit: Int = 100, offset: Long = 0): Page<OAuthClient>
    suspend fun insert(client: OAuthClient): OAuthClient
    suspend fun update(client: OAuthClient): OAuthClient
    suspend fun updateSecret(clientId: ClientId, secretHash: String, at: Instant)
    suspend fun delete(clientId: ClientId): Boolean
    suspend fun listScopes(): List<Scope>
}

interface ConsentRepository {
    suspend fun find(userId: UserId, clientId: ClientId): Consent?
    suspend fun grant(consent: Consent): Consent
    suspend fun revoke(userId: UserId, clientId: ClientId, at: Instant): Boolean
    suspend fun listForUser(userId: UserId): List<Consent>
}

interface RoleRepository {
    suspend fun listRoles(): List<Role>
    suspend fun findRole(name: String): Role?
    suspend fun upsertRole(role: Role): Role
    suspend fun deleteRole(name: String): Boolean
    suspend fun rolesOf(userId: UserId): Set<String>
    suspend fun assign(userId: UserId, roleNames: Set<String>)

    /** Flattened permission set, computed in the database to avoid an N+1 on every request. */
    suspend fun permissionsOf(userId: UserId): Set<dev.kamiql.helium.domain.policy.Permission>
}

interface SigningKeyRepository {
    suspend fun findActive(): SigningKey?
    suspend fun findById(id: SigningKeyId): SigningKey?

    /** Everything a verifier should accept, i.e. every non-retired key. */
    suspend fun listPublishable(): List<SigningKey>

    suspend fun insert(key: SigningKey): SigningKey
    suspend fun promote(id: SigningKeyId, at: Instant)
    suspend fun retire(id: SigningKeyId, at: Instant)
}

/**
 * Records access tokens revoked before their expiry, so `/introspect` can answer `active:
 * false` for a JWT that is still cryptographically valid.
 *
 * Bounded by the access-token lifetime: entries are dropped once the token would have expired
 * anyway, which keeps this table tiny.
 */
interface RevokedTokenRepository {
    suspend fun revoke(tokenId: String, expiresAt: Instant, at: Instant)
    suspend fun isRevoked(tokenId: String): Boolean
    suspend fun deleteExpired(before: Instant): Int
}
