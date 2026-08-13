package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.credential.PasswordHash
import dev.kamiql.helium.domain.credential.PasswordHashParameters
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.RecoveryCode
import dev.kamiql.helium.domain.mfa.TotpFactor
import dev.kamiql.helium.domain.mfa.UserVerificationRequirement
import dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions
import dev.kamiql.helium.domain.mfa.WebAuthnRegistrationOptions
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.FlowResult
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimitDecision
import dev.kamiql.helium.flow.port.RateLimitKey
import dev.kamiql.helium.flow.port.RateLimiter
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.MfaMethod
import dev.kamiql.helium.spi.MfaMethodRegistry
import dev.kamiql.helium.spi.RecoveryCodeIssuer
import dev.kamiql.helium.spi.VerificationChallenge
import java.time.Duration
import java.time.Instant

/**
 * Fakes and a fixture for [WebAuthnFlowsTest], extending the set in `TrustedDeviceFakes.kt`.
 *
 * The WebAuthn method fake derives `isEnrolled` from the factor table rather than from a private
 * set, so activating a factor through the flow really does change what the registry reports —
 * which is what the "first factor only" recovery-code rule turns on.
 */

internal const val PASSKEY_CREDENTIAL_ID: String = "Y3JlZGVudGlhbC1pZA"
internal const val PASSKEY_RP_ID: String = "id.example.test"

// --- repositories ---------------------------------------------------------------

internal class InMemoryMfaRepository : MfaRepository {
    private val factors = mutableListOf<MfaFactor>()

    fun rows(): List<MfaFactor> = factors.toList()

    override suspend fun listFactors(userId: UserId): List<MfaFactor> =
        factors.filter { it.userId == userId }

    override suspend fun findFactor(id: MfaFactorId): MfaFactor? = factors.firstOrNull { it.id == id }

    override suspend fun findActiveFactorOfType(userId: UserId, type: MfaType): MfaFactor? =
        factors.firstOrNull { it.userId == userId && it.type == type && it.isActive }

    override suspend fun insertFactor(factor: MfaFactor): MfaFactor = factor.also { factors += it }

    override suspend fun activateFactor(id: MfaFactorId, at: Instant) =
        replace(id) { it.copy(status = MfaFactorStatus.ACTIVE) }

    override suspend fun relabelFactor(id: MfaFactorId, label: String) =
        replace(id) { it.copy(label = label) }

    override suspend fun revokeFactor(id: MfaFactorId, at: Instant) =
        replace(id) { it.copy(status = MfaFactorStatus.REVOKED) }

    override suspend fun touchFactor(id: MfaFactorId, at: Instant) =
        replace(id) { it.copy(lastUsedAt = at) }

    private fun replace(id: MfaFactorId, update: (MfaFactor) -> MfaFactor) {
        val index = factors.indexOfFirst { it.id == id }
        if (index >= 0) factors[index] = update(factors[index])
    }

    override suspend fun findTotp(factorId: MfaFactorId): TotpFactor? = notUsed()
    override suspend fun insertTotp(factor: TotpFactor) = notUsed()
    override suspend fun tryAdvanceTotpStep(factorId: MfaFactorId, step: Long): Boolean = notUsed()
    override suspend fun replaceRecoveryCodes(userId: UserId, codes: List<RecoveryCode>) = notUsed()
    override suspend fun listRecoveryCodes(userId: UserId): List<RecoveryCode> = notUsed()
    override suspend fun consumeRecoveryCode(userId: UserId, codeHash: String, at: Instant): Boolean = notUsed()
    override suspend fun countUnusedRecoveryCodes(userId: UserId): Int = notUsed()
}

/** Hands out predictable plaintext and, crucially, tracks how many sets it has ever issued. */
internal class InMemoryRecoveryCodeIssuer : RecoveryCodeIssuer {
    private val issued = mutableMapOf<UserId, List<String>>()

    var generations: Int = 0
        private set

    override suspend fun generate(userId: UserId, now: Instant): List<String> {
        generations++
        return List(8) { index -> "recovery-$generations-$index" }.also { issued[userId] = it }
    }

    override suspend fun remaining(userId: UserId): Int = issued[userId]?.size ?: 0

    /** Simulates a user who has spent every code they were given. */
    fun exhaust(userId: UserId) {
        issued[userId] = emptyList()
    }
}

// --- MFA methods ---------------------------------------------------------------

/**
 * A passkey method backed by [factors].
 *
 * `beginEnrollment` writes a `PENDING` row exactly as a real adapter must, so a test that
 * confirms a factor id it was never given is exercising the same ownership check production
 * would hit.
 */
internal class FakeWebAuthnMethod(private val factors: InMemoryMfaRepository) : MfaMethod {

    override val type: MfaType = MfaType.WEBAUTHN

    var verificationChallenges: Int = 0
        private set

    /** Makes the authenticator response fail validation, as a forged attestation would. */
    var rejectEnrollment: Boolean = false

    override suspend fun beginEnrollment(userId: UserId, now: Instant): EnrollmentChallenge {
        val factorId = MfaFactorId.random()
        factors.insertFactor(
            MfaFactor(
                id = factorId,
                userId = userId,
                type = MfaType.WEBAUTHN,
                label = "Security key",
                status = MfaFactorStatus.PENDING,
                createdAt = now,
                lastUsedAt = null,
            ),
        )
        return EnrollmentChallenge.WebAuthn(
            factorId = factorId,
            options = WebAuthnRegistrationOptions(
                challenge = "challenge-$factorId",
                rpId = PASSKEY_RP_ID,
                rpName = "Helium",
                userHandle = userId.value.toString(),
                userName = "user",
                userDisplayName = "Test User",
                algorithms = WebAuthnRegistrationOptions.DEFAULT_ALGORITHMS,
                excludeCredentialIds = emptyList(),
                userVerification = UserVerificationRequirement.PREFERRED,
                timeout = Duration.ofMinutes(2),
            ),
        )
    }

    override suspend fun confirmEnrollment(
        factorId: MfaFactorId,
        response: MfaResponse,
        now: Instant,
    ): Boolean {
        if (rejectEnrollment) return false
        if (response !is MfaResponse.WebAuthnRegistration) return false
        if (response.credentialId != PASSKEY_CREDENTIAL_ID) return false
        factors.activateFactor(factorId, now)
        return true
    }

    override suspend fun beginVerification(userId: UserId, now: Instant): VerificationChallenge {
        verificationChallenges++
        return VerificationChallenge.WebAuthn(
            WebAuthnAuthenticationOptions(
                challenge = "assertion-challenge-$verificationChallenges",
                rpId = PASSKEY_RP_ID,
                allowCredentialIds = factors.listFactors(userId)
                    .filter { it.type == MfaType.WEBAUTHN && it.isActive }
                    .map { PASSKEY_CREDENTIAL_ID },
                userVerification = UserVerificationRequirement.PREFERRED,
                timeout = Duration.ofMinutes(2),
            ),
        )
    }

    override suspend fun verify(userId: UserId, response: MfaResponse, now: Instant): MfaVerificationResult {
        val assertion = response as? MfaResponse.WebAuthnAssertion ?: return MfaVerificationResult.Rejected
        if (assertion.credentialId != PASSKEY_CREDENTIAL_ID) return MfaVerificationResult.Rejected
        val factor = factors.listFactors(userId)
            .firstOrNull { it.type == MfaType.WEBAUTHN && it.isActive }
            ?: return MfaVerificationResult.Rejected
        return MfaVerificationResult.Verified(factor.id, acceptedStep = null)
    }

    override suspend fun isEnrolled(userId: UserId): Boolean =
        factors.listFactors(userId).any { it.type == MfaType.WEBAUTHN && it.isActive }
}

/** A well-formed registration response; the only one [FakeWebAuthnMethod] accepts. */
internal fun passkeyRegistration(): MfaResponse.WebAuthnRegistration =
    MfaResponse.WebAuthnRegistration(
        credentialId = PASSKEY_CREDENTIAL_ID,
        clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
        attestationObject = "o2NmbXRkbm9uZQ",
        transports = listOf("internal"),
    )

// --- rate limiting ---------------------------------------------------------------

/**
 * Records every permit consumed, and can be told to deny one dimension.
 *
 * Recording is the point: "this flow is rate limited" is otherwise an invisible property that
 * nothing fails when someone deletes the requirement.
 */
internal class RecordingRateLimiter : RateLimiter {
    val consumed = mutableListOf<RateLimitKey>()
    var denied: String? = null

    override suspend fun consume(key: RateLimitKey, limit: RateLimit): RateLimitDecision {
        consumed += key
        return if (key.dimension == denied) {
            RateLimitDecision.Limited(Duration.ofMinutes(5))
        } else {
            RateLimitDecision.Allowed(limit.permits)
        }
    }

    override suspend fun reset(key: RateLimitKey) = Unit

    fun dimensions(): List<String> = consumed.map { it.dimension }
}

private fun notUsed(): Nothing =
    error("this port is not exercised by the passkey suite; a call here is a test defect")

// --- fixture -----------------------------------------------------------------------

/**
 * Wires the real [MfaFlows] onto the fakes above with an authenticated, recently reauthenticated
 * caller — the state every flow in the class demands before it will do anything.
 */
internal class MfaFixture(private val lifetimes: Lifetimes = Lifetimes.DEFAULT) {

    val users = InMemoryUserRepository()
    val credentials = InMemoryPasswordCredentialRepository()
    val sessions = InMemorySessionRepository()
    val devices = InMemoryTrustedDeviceRepository()
    val outbox = RecordingOutbox()
    val transactions = RollbackSimulatingTransactionManager(devices, outbox)
    val audit = RecordingAudit()
    val mfaRepository = InMemoryMfaRepository()
    val recoveryCodes = InMemoryRecoveryCodeIssuer()
    val webauthn = FakeWebAuthnMethod(mfaRepository)
    val rateLimiter = RecordingRateLimiter()

    private val random = SequentialRandomSource()
    private val tokenHasher = PrefixTokenHasher()

    val trustedDevices = TrustedDeviceService(
        devices = devices,
        random = random,
        tokenHasher = tokenHasher,
        lifetimes = lifetimes,
        transactionManager = transactions,
        outbox = outbox,
    )

    val flows = MfaFlows(
        users = users,
        credentials = credentials,
        sessions = sessions,
        mfaRepository = mfaRepository,
        mfaMethods = MfaMethodRegistry(listOf(FakeTotpMethod(), webauthn)),
        recoveryCodes = recoveryCodes,
        passwordHasher = FakePasswordHasher(),
        rateLimiter = rateLimiter,
        trustedDevices = trustedDevices,
        lifetimes = lifetimes,
    )

    private val runner = FlowRunner(transactions, outbox, audit)

    /** Creates an account together with the live session the caller acts through. */
    suspend fun createUser(name: String, authenticatedAt: Instant = T0): Actor {
        val userId = UserId.random()
        users.add(
            User(
                id = userId,
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
        credentials.put(userId, PasswordHash("fake", PASSWORD, PasswordHashParameters.DEFAULT), T0)

        val sessionId = SessionId.random()
        sessions.insert(
            Session(
                id = sessionId,
                userId = userId,
                clientId = null,
                createdAt = T0,
                lastSeenAt = T0,
                idleExpiresAt = T0.plus(lifetimes.sessionIdle),
                absoluteExpiresAt = T0.plus(lifetimes.sessionAbsolute),
                revokedAt = null,
                authenticatedAt = authenticatedAt,
                authenticationMethods = setOf(AuthenticationMethod.PASSWORD),
                ipHash = null,
                userAgentHash = null,
                deviceLabel = null,
            ),
            sessionHash = "hash-$sessionId",
        )
        return Actor(userId, sessionId)
    }

    data class Actor(val userId: UserId, val sessionId: SessionId)

    fun context(actor: Actor, now: Instant = T0): FlowContext = FlowContext(
        requestId = RequestId("req_passkey"),
        actor = Principal.UserSession(
            userId = actor.userId,
            sessionId = actor.sessionId,
            permissions = setOf(Permission.ACCOUNT_MFA_MANAGE),
            roles = setOf("USER"),
            authenticationMethods = setOf(AuthenticationMethod.PASSWORD),
            emailVerified = true,
        ),
        ipAddress = "203.0.113.10",
        userAgent = USER_AGENT,
        now = now,
    )

    suspend fun beginEnrollment(
        actor: Actor,
        label: String? = "Yubikey",
        now: Instant = T0,
    ): FlowResult<WebAuthnEnrollmentStarted> = runner.execute(
        flows.beginWebAuthnEnrollment,
        BeginWebAuthnEnrollmentCommand(label),
        context(actor, now),
    )

    suspend fun confirmEnrollment(
        actor: Actor,
        factorId: MfaFactorId,
        response: MfaResponse.WebAuthnRegistration = passkeyRegistration(),
        label: String? = "Yubikey",
        now: Instant = T0,
    ): FlowResult<WebAuthnEnrollmentConfirmed> = runner.execute(
        flows.confirmWebAuthnEnrollment,
        ConfirmWebAuthnEnrollmentCommand(factorId, label = label, response = response),
        context(actor, now),
    )

    /** Enrolls and activates a passkey, returning its factor id. */
    suspend fun enrollPasskey(actor: Actor, now: Instant = T0): MfaFactorId {
        val started = runner.execute(
            flows.beginWebAuthnEnrollment,
            BeginWebAuthnEnrollmentCommand("Yubikey"),
            context(actor, now),
        )
        val factorId = (started as FlowResult.Success).value.factorId
        confirmEnrollment(actor, factorId, now = now)
        return factorId
    }

    suspend fun removeCredential(
        actor: Actor,
        factorId: MfaFactorId,
        currentPassword: String? = PASSWORD,
        now: Instant = T0,
    ): FlowResult<Unit> = runner.execute(
        flows.removeWebAuthnCredential,
        RemoveWebAuthnCredentialCommand(factorId, currentPassword?.let(Secret::of)),
        context(actor, now),
    )

    suspend fun trustADevice(actor: Actor, now: Instant = T0) {
        requireNotNull(trustedDevices.remember(actor.userId, context(actor, now), now))
    }
}
