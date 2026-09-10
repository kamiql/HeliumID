package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.Normalization
import dev.kamiql.helium.domain.common.RefreshTokenFamilyId
import dev.kamiql.helium.domain.common.RefreshTokenId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.TrustedDeviceId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.credential.BreachedPasswordChecker
import dev.kamiql.helium.domain.credential.PasswordCredential
import dev.kamiql.helium.domain.credential.PasswordHash
import dev.kamiql.helium.domain.credential.PasswordHashParameters
import dev.kamiql.helium.domain.credential.PasswordHasher
import dev.kamiql.helium.domain.credential.PasswordPolicy
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.TokenHasher
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.event.VerificationPurpose
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaPolicy
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.repository.Page
import dev.kamiql.helium.domain.repository.PasswordCredentialRepository
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.domain.repository.RoleRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.StoredVerificationToken
import dev.kamiql.helium.domain.repository.TrustedDeviceRepository
import dev.kamiql.helium.domain.repository.UserQuery
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.repository.VerificationTokenRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.domain.session.TrustedDevice
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import dev.kamiql.helium.domain.token.RefreshToken
import dev.kamiql.helium.domain.token.RefreshTokenFamily
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.FlowResult
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.port.AuditEntry
import dev.kamiql.helium.flow.port.AuditPort
import dev.kamiql.helium.flow.port.OutboxContext
import dev.kamiql.helium.flow.port.OutboxPort
import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimitDecision
import dev.kamiql.helium.flow.port.RateLimitKey
import dev.kamiql.helium.flow.port.RateLimiter
import dev.kamiql.helium.flow.port.SecurityTransactionStore
import dev.kamiql.helium.flow.port.TransactionManager
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.MfaMethod
import dev.kamiql.helium.spi.MfaMethodRegistry
import java.time.Duration
import java.time.Instant
import kotlin.test.assertIs

/**
 * Fakes and a fixture for [TrustedDeviceTest].
 *
 * Hand written rather than mocked, in the style of `FlowRunnerTest`: the properties under test
 * are conditional updates, rotation and transaction unwinding, and a stubbed return value can
 * model none of those.
 */

internal val T0: Instant = Instant.parse("2026-08-12T10:00:00Z")
internal val DAY_1: Instant = T0.plus(Duration.ofDays(1))
internal val DAY_2: Instant = T0.plus(Duration.ofDays(2))
internal val DAY_3: Instant = T0.plus(Duration.ofDays(3))

/** Past the 30-day default in [Lifetimes.trustedDevice]. */
internal val AFTER_TRUST_EXPIRY: Instant = T0.plus(Duration.ofDays(31))

internal const val PASSWORD: String = "correct-horse-battery-staple"
internal const val TOTP_CODE: String = "123456"
internal const val USER_AGENT: String = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"

// --- crypto ports -------------------------------------------------------------

/** Pinned token generator: every secret in a test run is predictable and distinct. */
internal class SequentialRandomSource : RandomSource {
    private var counter = 0

    override fun bytes(length: Int): ByteArray {
        counter++
        return ByteArray(length) { index -> (counter + index).toByte() }
    }

    override fun token(byteLength: Int): String = "token-${++counter}"

    override fun humanCode(groups: Int, groupLength: Int): String = "code-${++counter}"
}

internal class PrefixTokenHasher : TokenHasher {
    override fun hash(token: String): String = "hmac:$token"
    override fun matches(token: String, hash: String): Boolean = this.hash(token) == hash
}

internal class FakePasswordHasher : PasswordHasher {
    override suspend fun hash(password: Secret): PasswordHash =
        PasswordHash("fake", password.reveal(), PasswordHashParameters.DEFAULT)

    override suspend fun verify(password: Secret, hash: PasswordHash): Boolean =
        hash.encoded == password.reveal()

    override suspend fun verifyDummy(password: Secret): Boolean = false

    override fun needsRehash(hash: PasswordHash): Boolean = false
}

// --- repositories ---------------------------------------------------------------

internal class InMemoryUserRepository : UserRepository {
    private val stored = mutableListOf<User>()

    fun add(user: User) {
        stored += user
    }

    override suspend fun findById(id: UserId): User? = stored.firstOrNull { it.id == id }

    override suspend fun findByUsername(username: Username): User? =
        stored.firstOrNull { it.username.normalized == username.normalized }

    override suspend fun findByEmail(email: EmailAddress): User? =
        stored.firstOrNull { it.primaryEmail.normalized == email.normalized }

    override suspend fun findByLoginIdentifier(identifier: String): User? {
        val folded = Normalization.fold(identifier)
        return stored.firstOrNull {
            it.username.normalized == folded || it.primaryEmail.normalized == folded
        }
    }

    override suspend fun insert(user: User): User = user.also { stored += it }

    override suspend fun update(user: User): User = unused()
    override suspend fun updateStatus(id: UserId, status: UserStatus, at: Instant) = unused()
    override suspend fun markEmailVerified(id: UserId, at: Instant) = unused()
    override suspend fun changePrimaryEmail(id: UserId, email: EmailAddress, verifiedAt: Instant) = unused()
    override suspend fun softDelete(id: UserId, at: Instant) = unused()
    override suspend fun search(query: UserQuery): Page<User> = unused()
}

internal class InMemoryPasswordCredentialRepository : PasswordCredentialRepository {
    private val stored = mutableMapOf<UserId, PasswordCredential>()

    fun put(userId: UserId, hash: PasswordHash, at: Instant) {
        stored[userId] = PasswordCredential(userId, hash, changedAt = at, createdAt = at)
    }

    override suspend fun findByUserId(userId: UserId): PasswordCredential? = stored[userId]

    override suspend fun upsert(userId: UserId, hash: PasswordHash, at: Instant) {
        stored[userId] = PasswordCredential(userId, hash, changedAt = at, createdAt = at)
    }

    override suspend fun delete(userId: UserId) {
        stored -= userId
    }
}

internal class InMemorySessionRepository : SessionRepository {
    private val stored = mutableListOf<Session>()

    fun rows(): List<Session> = stored.toList()

    override suspend fun findById(id: SessionId): Session? = stored.firstOrNull { it.id == id }

    override suspend fun findByHash(sessionHash: String): Session? = unused()

    override suspend fun listActiveForUser(userId: UserId, now: Instant): List<Session> =
        stored.filter { it.userId == userId && it.isActive(now) }

    override suspend fun insert(session: Session, sessionHash: String): Session =
        session.also { stored += it }

    override suspend fun touch(id: SessionId, now: Instant, idleExpiresAt: Instant) = unused()

    override suspend fun revoke(id: SessionId, at: Instant, reason: SessionRevocationReason): Boolean =
        revokeWhere(at) { it.id == id } > 0

    override suspend fun revokeAllForUser(
        userId: UserId,
        at: Instant,
        reason: SessionRevocationReason,
        except: SessionId?,
    ): Int = revokeWhere(at) { it.userId == userId && it.id != except }

    /** Only ever revokes rows that are still live, as the conditional UPDATE in Postgres does. */
    private fun revokeWhere(at: Instant, matches: (Session) -> Boolean): Int {
        var revoked = 0
        stored.replaceAll { session ->
            if (session.revokedAt != null || !matches(session)) session
            else session.copy(revokedAt = at).also { revoked++ }
        }
        return revoked
    }

    /** Merges rather than replaces, and skips revoked rows, exactly as the SQL does. */
    override suspend fun markAuthenticated(
        id: SessionId,
        at: Instant,
        methods: Set<AuthenticationMethod>,
    ): Boolean {
        val index = stored.indexOfFirst { it.id == id && it.revokedAt == null }
        if (index < 0) return false
        stored[index] = stored[index].let {
            it.copy(authenticatedAt = at, authenticationMethods = it.authenticationMethods + methods)
        }
        return true
    }

    override suspend fun deleteExpired(before: Instant): Int = unused()
}

internal class InMemoryRoleRepository : RoleRepository {
    private val granted = mutableMapOf<UserId, Set<Permission>>()

    fun grant(userId: UserId, permissions: Set<Permission>) {
        granted[userId] = permissions
    }

    override suspend fun permissionsOf(userId: UserId): Set<Permission> = granted[userId].orEmpty()

    override suspend fun rolesOf(userId: UserId): Set<String> = emptySet()

    override suspend fun assign(userId: UserId, roleNames: Set<String>) = Unit

    override suspend fun listRoles(): List<Role> = unused()
    override suspend fun findRole(name: String): Role? = unused()
    override suspend fun upsertRole(role: Role): Role = unused()
    override suspend fun deleteRole(name: String): Boolean = unused()
}

/**
 * The device table.
 *
 * [rotate] and [revoke] are conditional updates keyed on the state they expect to find, exactly
 * as the Postgres implementation must be — a fake that unconditionally overwrote the row would
 * hide the very races those signatures exist to close.
 *
 * The call counters exist for the privileged-account case, where the assertion is not "the token
 * was rejected" but "the token was never looked at".
 */
internal class InMemoryTrustedDeviceRepository : TrustedDeviceRepository {
    private val stored = mutableListOf<TrustedDevice>()

    var lookups: Int = 0
        private set

    var rotations: Int = 0
        private set

    fun rows(): List<TrustedDevice> = stored.toList()

    /** Restores [base], then re-applies [survivors] — see [RollbackSimulatingTransactionManager]. */
    fun reset(base: List<TrustedDevice>, survivors: List<TrustedDevice>) {
        stored.clear()
        stored += base
        survivors.forEach { survivor ->
            val index = stored.indexOfFirst { it.id == survivor.id }
            if (index >= 0) stored[index] = survivor else stored += survivor
        }
    }

    override suspend fun findByHash(userId: UserId, tokenHash: String): TrustedDevice? {
        lookups++
        return stored.firstOrNull { it.userId == userId && it.tokenHash == tokenHash }
    }

    override suspend fun findByPreviousHash(userId: UserId, tokenHash: String): TrustedDevice? {
        lookups++
        return stored.firstOrNull { it.userId == userId && it.previousTokenHash == tokenHash }
    }

    override suspend fun listActiveForUser(userId: UserId, now: Instant): List<TrustedDevice> =
        stored.filter { it.userId == userId && it.isActive(now) }

    override suspend fun insert(device: TrustedDevice): TrustedDevice = device.also { stored += it }

    override suspend fun rotate(
        id: TrustedDeviceId,
        expectedHash: String,
        newHash: String,
        at: Instant,
    ): Boolean {
        rotations++
        val index = stored.indexOfFirst {
            it.id == id && it.tokenHash == expectedHash && it.revokedAt == null
        }
        if (index < 0) return false
        stored[index] = stored[index].copy(
            tokenHash = newHash,
            previousTokenHash = expectedHash,
            lastUsedAt = at,
        )
        return true
    }

    override suspend fun revoke(
        userId: UserId,
        id: TrustedDeviceId,
        at: Instant,
        reason: TrustedDeviceRevocationReason,
    ): Boolean {
        val index = stored.indexOfFirst { it.userId == userId && it.id == id && it.revokedAt == null }
        if (index < 0) return false
        stored[index] = stored[index].copy(
            revokedAt = at,
            revokedReason = reason,
            // Only the reuse case discards the superseded generation; every other revocation
            // keeps it so a later replay is still recognisable. Mirrors the Postgres behaviour.
            previousTokenHash = if (reason == TrustedDeviceRevocationReason.REUSE_DETECTED) {
                null
            } else {
                stored[index].previousTokenHash
            },
        )
        return true
    }

    /**
     * Clearing the superseded hash is the claim, so the second caller finds nothing to match and
     * loses — which is what makes reuse reporting exactly-once.
     */
    override suspend fun claimReuse(
        userId: UserId,
        deviceId: TrustedDeviceId,
        previousTokenHash: String,
        at: Instant,
    ): Boolean {
        val index = stored.indexOfFirst {
            it.userId == userId && it.id == deviceId && it.previousTokenHash == previousTokenHash
        }
        if (index < 0) return false
        val row = stored[index]
        stored[index] = row.copy(
            previousTokenHash = null,
            // An earlier revocation for another reason keeps its own timestamp and reason.
            revokedAt = row.revokedAt ?: at,
            revokedReason = row.revokedReason ?: TrustedDeviceRevocationReason.REUSE_DETECTED,
        )
        return true
    }

    override suspend fun revokeAllForUser(
        userId: UserId,
        at: Instant,
        reason: TrustedDeviceRevocationReason,
    ): Int {
        var count = 0
        stored.indices.forEach { index ->
            val device = stored[index]
            if (device.userId == userId && device.revokedAt == null) {
                stored[index] = device.copy(revokedAt = at, revokedReason = reason)
                count++
            }
        }
        return count
    }

    override suspend fun deleteExpired(before: Instant): Int =
        stored.count { !it.expiresAt.isAfter(before) }
            .also { stored.removeAll { device -> !device.expiresAt.isAfter(before) } }
}

/** Refresh tokens play no part in these flows; every call is a bug in the test. */
internal class UnusedRefreshTokenRepository : RefreshTokenRepository {
    override suspend fun createFamily(family: RefreshTokenFamily): RefreshTokenFamily = unused()
    override suspend fun findFamily(id: RefreshTokenFamilyId): RefreshTokenFamily? = unused()
    override suspend fun insertToken(token: RefreshToken): RefreshToken = unused()
    override suspend fun findByHash(tokenHash: String): RefreshToken? = unused()
    override suspend fun markUsed(tokenId: RefreshTokenId, at: Instant, replacedBy: RefreshTokenId): Boolean = unused()
    override suspend fun revokeFamily(familyId: RefreshTokenFamilyId, at: Instant, reuseDetected: Boolean): Int = unused()
    override suspend fun revokeFamiliesForUser(userId: UserId, at: Instant): Int = unused()
    override suspend fun revokeFamiliesForSession(sessionId: SessionId, at: Instant): Int = unused()
    override suspend fun listActiveFamiliesForUser(userId: UserId, now: Instant): List<RefreshTokenFamily> = unused()
    override suspend fun revokeFamiliesForUserAndClient(userId: UserId, clientId: ClientId, at: Instant): Int =
        unused()
    override suspend fun deleteExpired(before: Instant): Int = unused()
}

internal class UnusedVerificationTokenRepository : VerificationTokenRepository {
    override suspend fun insert(token: StoredVerificationToken) = unused()
    override suspend fun findByHash(tokenHash: String, purpose: VerificationPurpose): StoredVerificationToken? = unused()
    override suspend fun consume(tokenHash: String, purpose: VerificationPurpose, at: Instant): Boolean = unused()
    override suspend fun invalidateAllForUser(userId: UserId, purpose: VerificationPurpose, at: Instant): Int = unused()
    override suspend fun deleteExpired(before: Instant): Int = unused()
}

// --- flow-engine ports ------------------------------------------------------------

/**
 * Applies writes for real and undoes them when the transaction unwinds.
 *
 * The recording manager in `FlowRunnerTest` counts commits; this one also has to *simulate* the
 * rollback, because the trusted-device reuse case turns on the difference between a write that
 * outlived an unwound transaction and one that was merely never undone. Rows and events written
 * inside [requiresNew] are re-applied after the enclosing rollback, which is what an independent
 * database transaction does.
 */
internal class RollbackSimulatingTransactionManager(
    private val devices: InMemoryTrustedDeviceRepository,
    private val outbox: RecordingOutbox,
) : TransactionManager {

    var opened: Int = 0
        private set

    var committed: Int = 0
        private set

    var rolledBack: Int = 0
        private set

    var independentCommits: Int = 0
        private set

    private var survivingDevices = emptyList<TrustedDevice>()
    private var survivingEvents = emptyList<DomainEvent>()

    override suspend fun <T> transaction(block: suspend () -> T): T {
        opened++
        val deviceRows = devices.rows()
        val events = outbox.rows()
        survivingDevices = emptyList()
        survivingEvents = emptyList()
        return try {
            block().also { committed++ }
        } catch (error: Throwable) {
            rolledBack++
            devices.reset(deviceRows, survivingDevices)
            outbox.reset(events, survivingEvents)
            throw error
        }
    }

    override suspend fun <T> requiresNew(block: suspend () -> T): T {
        val deviceRows = devices.rows()
        val events = outbox.rows()
        return block().also {
            independentCommits++
            survivingDevices = survivingDevices + devices.rows().filterNot { row -> row in deviceRows }
            survivingEvents = survivingEvents + outbox.rows().filterNot { event -> event in events }
        }
    }
}

internal class RecordingOutbox : OutboxPort {
    val published = mutableListOf<DomainEvent>()

    fun rows(): List<DomainEvent> = published.toList()

    fun reset(base: List<DomainEvent>, survivors: List<DomainEvent>) {
        published.clear()
        published += base
        published += survivors
    }

    override suspend fun publish(events: List<DomainEvent>, context: OutboxContext) {
        published += events
    }
}

internal class RecordingAudit : AuditPort {
    val entries = mutableListOf<AuditEntry>()

    override suspend fun record(entry: AuditEntry) {
        entries += entry
    }
}

internal object AllowAllRateLimiter : RateLimiter {
    override suspend fun consume(key: RateLimitKey, limit: RateLimit): RateLimitDecision =
        RateLimitDecision.Allowed(limit.permits)

    override suspend fun reset(key: RateLimitKey) = Unit
}

/** Redis stands in for this in production; it is deliberately outside the database transaction. */
internal class InMemorySecurityTransactionStore : SecurityTransactionStore {
    private val stored = mutableMapOf<Pair<String, String>, String>()

    override suspend fun put(id: TransactionId, kind: String, payload: String, ttl: Duration) {
        stored[id.value to kind] = payload
    }

    override suspend fun peek(id: TransactionId, kind: String): String? = stored[id.value to kind]

    override suspend fun take(id: TransactionId, kind: String): String? = stored.remove(id.value to kind)

    override suspend fun delete(id: TransactionId, kind: String) {
        stored -= id.value to kind
    }

    override suspend fun increment(id: TransactionId, kind: String, ttl: Duration): Long = unused()
}

internal class FakeTotpMethod : MfaMethod {
    private val enrolled = mutableSetOf<UserId>()

    override val type: MfaType = MfaType.TOTP

    fun enroll(userId: UserId) {
        enrolled += userId
    }

    override suspend fun verify(userId: UserId, response: MfaResponse, now: Instant): MfaVerificationResult =
        if ((response as? MfaResponse.Code)?.value?.reveal() == TOTP_CODE) {
            MfaVerificationResult.Verified(MfaFactorId.random(), acceptedStep = 1)
        } else {
            MfaVerificationResult.Rejected
        }

    override suspend fun isEnrolled(userId: UserId): Boolean = userId in enrolled

    override suspend fun beginEnrollment(userId: UserId, now: Instant): EnrollmentChallenge = unused()
    override suspend fun confirmEnrollment(factorId: MfaFactorId, response: MfaResponse, now: Instant): Boolean =
        unused()
}

private fun unused(): Nothing =
    error("this port is not exercised by the trusted-device suite; a call here is a test defect")

// --- fixture -----------------------------------------------------------------------

/**
 * Wires the real [IdentityFlows], [SessionService] and [TrustedDeviceService] onto the fakes
 * above.
 *
 * The services under test are the real ones: the point of the suite is the policy those classes
 * encode, so replacing any of them with a double would test the fixture instead.
 */
internal class TrustedDeviceFixture(
    lifetimes: Lifetimes = Lifetimes.DEFAULT,
    mfaPolicy: MfaPolicy = MfaPolicy.OPTIONAL,
) {

    val users = InMemoryUserRepository()
    val credentials = InMemoryPasswordCredentialRepository()
    val sessions = InMemorySessionRepository()
    val roles = InMemoryRoleRepository()
    val devices = InMemoryTrustedDeviceRepository()
    val outbox = RecordingOutbox()
    val transactions = RollbackSimulatingTransactionManager(devices, outbox)
    val audit = RecordingAudit()
    val totp = FakeTotpMethod()
    val mfaRepository = InMemoryMfaRepository()
    val webauthn = FakeWebAuthnMethod(mfaRepository)

    private val random = SequentialRandomSource()
    private val tokenHasher = PrefixTokenHasher()
    private val securityTransactions = InMemorySecurityTransactionStore()

    val trustedDevices = TrustedDeviceService(
        devices = devices,
        random = random,
        tokenHasher = tokenHasher,
        lifetimes = lifetimes,
        transactionManager = transactions,
        outbox = outbox,
    )

    private val sessionService = SessionService(sessions, random, tokenHasher, lifetimes)

    val flows = IdentityFlows(
        users = users,
        credentials = credentials,
        sessions = sessions,
        roles = roles,
        refreshTokens = UnusedRefreshTokenRepository(),
        passwordHasher = FakePasswordHasher(),
        passwordPolicy = PasswordPolicyService(PasswordPolicy.DEFAULT, BreachedPasswordChecker.Disabled),
        sessionService = sessionService,
        trustedDevices = trustedDevices,
        verificationTokens = VerificationTokenService(
            UnusedVerificationTokenRepository(), random, tokenHasher, lifetimes,
        ),
        transactions = securityTransactions,
        mfaMethods = MfaMethodRegistry(listOf(totp, webauthn)),
        rateLimiter = AllowAllRateLimiter,
        random = random,
        lifetimes = lifetimes,
        mfaPolicy = mfaPolicy,
    )

    private val runner = FlowRunner(transactions, outbox, audit)

    fun context(now: Instant = T0): FlowContext = FlowContext(
        requestId = RequestId("req_trusted_device"),
        actor = Principal.Anonymous,
        ipAddress = "203.0.113.10",
        userAgent = USER_AGENT,
        now = now,
    )

    /**
     * Creates an active account.
     *
     * @param privileged grants a permission from [Permission.STEP_UP_REQUIRED], which is what
     *        the login flow reads to decide that no device may buy an exemption.
     */
    fun createUser(
        name: String,
        privileged: Boolean = false,
        mfaEnrolled: Boolean = true,
    ): UserId {
        val id = UserId.random()
        users.add(
            User(
                id = id,
                username = requireNotNull(Username.parse(name)),
                primaryEmail = requireNotNull(EmailAddress.parse("$name@example.test")),
                firstName = "Test",
                lastName = "User",
                status = UserStatus.ACTIVE,
                emailVerifiedAt = T0,
                createdAt = T0,
                updatedAt = T0,
                version = 0,
            ),
        )
        // The fake hasher treats the encoded form as the plaintext; nothing here is a real hash.
        credentials.put(id, PasswordHash("fake", PASSWORD, PasswordHashParameters.DEFAULT), T0)
        roles.grant(
            id,
            if (privileged) setOf(Permission.ACCOUNT_SESSION_MANAGE, Permission.ADMIN_USER_WRITE)
            else setOf(Permission.ACCOUNT_SESSION_MANAGE),
        )
        if (mfaEnrolled) totp.enroll(id)
        return id
    }

    suspend fun login(
        name: String,
        trustedDeviceToken: String? = null,
        now: Instant = T0,
    ): FlowResult<LoginSucceeded> = runner.execute(
        flows.login,
        LoginCommand(
            identifier = name,
            password = Secret.of(PASSWORD),
            trustedDeviceToken = trustedDeviceToken?.let(Secret::of),
        ),
        context(now),
    )

    suspend fun completeMfa(
        transactionId: TransactionId,
        rememberDevice: Boolean,
        now: Instant = T0,
        method: MfaType = MfaType.TOTP,
        response: MfaResponse = MfaResponse.Code(Secret.of(TOTP_CODE)),
    ): FlowResult<LoginSucceeded> = runner.execute(
        flows.completeMfa,
        CompleteMfaCommand(
            transactionId = transactionId,
            method = method,
            response = response,
            rememberDevice = rememberDevice,
        ),
        context(now),
    )

    /** Asks for the nonce a challenge-signing method needs. Must not consume the transaction. */
    suspend fun beginMfaChallenge(
        transactionId: TransactionId,
        method: MfaType = MfaType.TOTP,
        now: Instant = T0,
    ): FlowResult<MfaChallengeStarted> = runner.execute(
        flows.beginMfaChallenge,
        BeginMfaChallengeCommand(transactionId, method),
        context(now),
    )

    /**
     * The same request, made by somebody who is already signed in.
     *
     * Step-up flows read the session out of the principal rather than out of the command, so a
     * test for them cannot use the anonymous [context] the login tests share.
     */
    fun sessionContext(
        userId: UserId,
        sessionId: SessionId,
        now: Instant = T0,
        methods: Set<AuthenticationMethod> = setOf(AuthenticationMethod.PASSWORD),
    ): FlowContext = context(now).copy(
        actor = Principal.UserSession(
            userId = userId,
            sessionId = sessionId,
            permissions = setOf(Permission.ACCOUNT_SESSION_MANAGE),
            roles = emptySet(),
            authenticationMethods = methods,
            emailVerified = true,
        ),
    )

    /**
     * Signs [name] in all the way and hands back the session that resulted.
     *
     * Goes through the real flows rather than inserting a row, so the session under test carries
     * the `authenticatedAt` and `amr` a genuine sign-in leaves behind.
     */
    suspend fun signIn(name: String, now: Instant = T0): Session =
        when (val first = login(name, now = now)) {
            is FlowResult.Success -> first.value.session.session
            is FlowResult.Challenge -> assertIs<FlowResult.Success<LoginSucceeded>>(
                completeMfa(first.transactionId, rememberDevice = false, now = now),
            ).value.session.session

            is FlowResult.Failure -> error("sign-in for '$name' failed: ${first.error}")
        }

    suspend fun reauthenticate(
        session: Session,
        password: String = PASSWORD,
        now: Instant = T0,
    ): FlowResult<Unit> = runner.execute(
        flows.reauthenticate,
        ReauthenticateCommand(Secret.of(password)),
        sessionContext(session.userId, session.id, now, session.authenticationMethods),
    )

    /** A step-up attempted by somebody with no session at all. */
    suspend fun reauthenticateAnonymously(now: Instant = T0): FlowResult<Unit> =
        runner.execute(flows.reauthenticate, ReauthenticateCommand(Secret.of(PASSWORD)), context(now))

    suspend fun completeReauthentication(
        session: Session,
        transactionId: TransactionId,
        now: Instant = T0,
        method: MfaType = MfaType.TOTP,
        response: MfaResponse = MfaResponse.Code(Secret.of(TOTP_CODE)),
    ): FlowResult<Unit> = runner.execute(
        flows.completeReauthentication,
        CompleteReauthenticationCommand(transactionId, method, response),
        sessionContext(session.userId, session.id, now, session.authenticationMethods),
    )

    /** Writes an active passkey factor straight to the table, bypassing enrollment. */
    suspend fun seedPasskey(userId: UserId, now: Instant = T0): MfaFactorId {
        val id = MfaFactorId.random()
        mfaRepository.insertFactor(
            MfaFactor(
                id = id,
                userId = userId,
                type = MfaType.WEBAUTHN,
                label = "Yubikey",
                status = MfaFactorStatus.ACTIVE,
                createdAt = now,
                lastUsedAt = null,
            ),
        )
        return id
    }

    /** Signs in, answers the challenge with "trust this device", and returns the cookie value. */
    suspend fun trustThisDevice(name: String, now: Instant = T0): String {
        val challenge = assertIs<FlowResult.Challenge>(login(name, now = now))
        val success = assertIs<FlowResult.Success<LoginSucceeded>>(
            completeMfa(challenge.transactionId, rememberDevice = true, now = now),
        )
        return assertIs<TrustedDeviceDirective.Issue>(success.value.trustedDevice).device.cookieValue()
    }

    /**
     * Mints a device straight from the service, bypassing the flow's policy.
     *
     * The only way to give a privileged account a genuinely valid token, since the flow refuses
     * to mint one for them.
     */
    suspend fun mintDeviceOutsideTheFlow(userId: UserId, now: Instant = T0): String =
        requireNotNull(trustedDevices.remember(userId, context(now), now)).cookieValue()

    /** Writes a device row directly, for configurations in which the service will not mint one. */
    suspend fun seedDevice(userId: UserId, plaintext: String, now: Instant = T0): TrustedDeviceId {
        val id = TrustedDeviceId.random()
        devices.insert(
            TrustedDevice(
                id = id,
                userId = userId,
                tokenHash = tokenHasher.hash(plaintext),
                previousTokenHash = null,
                label = null,
                createdAt = now,
                lastUsedAt = now,
                expiresAt = now.plus(Duration.ofDays(30)),
                revokedAt = null,
                revokedReason = null,
            ),
        )
        return id
    }
}
