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
import dev.kamiql.helium.domain.common.TrustedDeviceId
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
import dev.kamiql.helium.domain.mfa.WebAuthnCredential
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.domain.session.TrustedDevice
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
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

interface TrustedDeviceRepository {

    /** Current-generation lookup. Bound to the user so a token cannot cross accounts. */
    suspend fun findByHash(userId: UserId, tokenHash: String): TrustedDevice?

    /**
     * Superseded-generation lookup, for reuse detection.
     *
     * Also matches already-revoked rows: a copied cookie replayed after the device was revoked
     * is still the event worth reporting, and dropping it would make reuse detection depend on
     * the order in which the two parties happen to log in.
     */
    suspend fun findByPreviousHash(userId: UserId, tokenHash: String): TrustedDevice?

    /**
     * Atomically claims a replayed generation as a reported incident.
     *
     * Clears `previousTokenHash` and, if the device is still live, revokes it as
     * [TrustedDeviceRevocationReason.REUSE_DETECTED]. A single conditional UPDATE, so of any
     * number of replays — concurrent or spread over weeks — exactly one caller sees `true`.
     *
     * That is the point: the caller notifies the account owner, and a security mail whose volume
     * an attacker controls by re-sending a cookie is worse than no mail. Revocation alone cannot
     * carry this, because a device revoked earlier for an unrelated reason is still worth one
     * report and would already have `revokedAt` set.
     *
     * @return `false` when this generation was already claimed, or never existed.
     */
    suspend fun claimReuse(
        userId: UserId,
        deviceId: TrustedDeviceId,
        previousTokenHash: String,
        at: Instant,
    ): Boolean

    suspend fun listActiveForUser(userId: UserId, now: Instant): List<TrustedDevice>

    suspend fun insert(device: TrustedDevice): TrustedDevice

    /**
     * Atomically advances a device to its next token.
     *
     * Implemented as a single conditional UPDATE keyed on the *current* hash, so two concurrent
     * logins presenting the same cookie produce exactly one valid successor. The loser sees
     * `false` and must fall back to a challenge rather than mint a second live token.
     *
     * @return `false` when the row no longer carries [expectedHash] — already rotated, revoked
     *         or gone.
     */
    suspend fun rotate(
        id: TrustedDeviceId,
        expectedHash: String,
        newHash: String,
        at: Instant,
    ): Boolean

    /**
     * Revokes one device, scoped to its owner.
     *
     * Keeps `previousTokenHash` for every reason except
     * [TrustedDeviceRevocationReason.REUSE_DETECTED], which is what lets a cookie copied *before*
     * an unrelated revocation still be recognised as a replay afterwards. Clearing it wholesale
     * would make detection depend on whether the owner happened to change their password first.
     *
     * For `REUSE_DETECTED` it *is* cleared: the theft is already known and reported, and leaving
     * the value indexed would let the holder of the stolen cookie trigger a fresh notification on
     * every retry.
     *
     * @return `false` when the device does not exist, belongs to someone else, or was already
     *         revoked — the caller must not distinguish the three.
     */
    suspend fun revoke(
        userId: UserId,
        id: TrustedDeviceId,
        at: Instant,
        reason: TrustedDeviceRevocationReason,
    ): Boolean

    /** @return number of devices revoked. */
    suspend fun revokeAllForUser(
        userId: UserId,
        at: Instant,
        reason: TrustedDeviceRevocationReason,
    ): Int

    /** Deletes devices whose expiry has passed. Called by the cleanup job. */
    suspend fun deleteExpired(before: Instant): Int
}

interface MfaRepository {
    suspend fun listFactors(userId: UserId): List<MfaFactor>
    suspend fun findFactor(id: MfaFactorId): MfaFactor?
    suspend fun findActiveFactorOfType(userId: UserId, type: MfaType): MfaFactor?
    suspend fun insertFactor(factor: MfaFactor): MfaFactor
    suspend fun activateFactor(id: MfaFactorId, at: Instant)

    /**
     * Renames a factor.
     *
     * A label is free text the user picked to tell two authenticators apart; it is never used for
     * lookup, so there is no uniqueness or normalization concern here. Length is bounded by the
     * caller, because the limit is a storage detail this port does not want to state.
     */
    suspend fun relabelFactor(id: MfaFactorId, label: String)

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

/**
 * Registered passkeys.
 *
 * Separate from [MfaRepository] because a credential is owned by an `MfaFactor` rather than
 * being one: the factor row carries status, label and revocation, and this table carries only
 * what the authenticator contributed. Revoking a factor cascades here.
 */
interface WebAuthnCredentialRepository {

    /** Active and pending credentials, used to build `excludeCredentials` and `allowCredentials`. */
    suspend fun listForUser(userId: UserId): List<WebAuthnCredential>

    suspend fun findByFactor(factorId: MfaFactorId): WebAuthnCredential?

    /**
     * Looks up the credential an assertion names.
     *
     * Scoped to [userId] on purpose: a credential id arrives from the client, and resolving it
     * globally would let an assertion produced for one account be presented against another.
     */
    suspend fun findByCredentialId(userId: UserId, credentialId: ByteArray): WebAuthnCredential?

    suspend fun insert(credential: WebAuthnCredential)

    /**
     * Conditionally advances the signature counter.
     *
     * @return `false` when [counter] does not exceed the stored value. That is the
     *         cloned-authenticator signal, and — as with the TOTP step guard — a single
     *         conditional UPDATE is what stops two concurrent assertions both succeeding with
     *         the same counter. Whether a non-advancing counter is fatal is the caller's
     *         decision, not this method's: many authenticators legitimately always report `0`.
     */
    suspend fun tryAdvanceSignatureCounter(factorId: MfaFactorId, counter: Long, at: Instant): Boolean

    /** Records use without touching the counter, for authenticators that do not keep one. */
    suspend fun touch(factorId: MfaFactorId, at: Instant)
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
    suspend fun findScope(name: String): Scope?

    /** Creates or replaces a scope. Never changes `builtIn` or the original creation time. */
    suspend fun upsertScope(scope: Scope, at: Instant): Scope

    suspend fun deleteScope(name: String): Boolean

    /**
     * How many registered clients still list this scope.
     *
     * `oauth_client_scopes.scope` cascades on delete, so dropping a scope that is still in use
     * would strip it from those clients without a word and only surface later as `invalid_scope`
     * on an authorization request. The delete path refuses instead.
     */
    suspend fun clientsUsingScope(name: String): Long
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
