package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.TrustedDeviceId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.common.VerificationTokenId
import dev.kamiql.helium.domain.credential.BreachedPasswordChecker
import dev.kamiql.helium.domain.credential.PasswordPolicy
import dev.kamiql.helium.domain.credential.PasswordPolicyResult
import dev.kamiql.helium.domain.credential.PasswordRejectionReason
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.TokenHasher
import dev.kamiql.helium.domain.event.VerificationPurpose
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.StoredVerificationToken
import dev.kamiql.helium.domain.repository.TrustedDeviceRepository
import dev.kamiql.helium.domain.repository.VerificationTokenRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.IssuedSession
import dev.kamiql.helium.domain.session.IssuedTrustedDevice
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.domain.session.TrustedDevice
import dev.kamiql.helium.domain.session.TrustedDeviceCheck
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.port.OutboxContext
import dev.kamiql.helium.flow.port.OutboxPort
import dev.kamiql.helium.flow.port.TransactionManager
import org.slf4j.LoggerFactory
import java.time.Instant

/**
 * Creates and validates browser sessions.
 *
 * The cookie value is 256 bits of randomness; only its HMAC is stored, so the sessions table
 * is not a list of valid credentials.
 */
class SessionService(
    private val sessions: SessionRepository,
    private val random: RandomSource,
    private val tokenHasher: TokenHasher,
    private val lifetimes: Lifetimes,
) {

    suspend fun issue(
        userId: UserId,
        clientId: ClientId?,
        methods: Set<AuthenticationMethod>,
        context: FlowContext,
    ): IssuedSession {
        val plaintext = random.token(32)
        val now = context.now
        val session = Session(
            id = SessionId.random(),
            userId = userId,
            clientId = clientId,
            createdAt = now,
            lastSeenAt = now,
            idleExpiresAt = now.plus(lifetimes.sessionIdle),
            absoluteExpiresAt = now.plus(lifetimes.sessionAbsolute),
            revokedAt = null,
            authenticatedAt = now,
            authenticationMethods = methods,
            ipHash = context.ipAddress?.let(FlowRunner::hashForAudit),
            userAgentHash = context.userAgent?.let(FlowRunner::hashForAudit),
            deviceLabel = context.userAgent?.let(::describeDevice),
        )
        sessions.insert(session, tokenHasher.hash(plaintext))
        return IssuedSession(session, plaintext)
    }

    /**
     * Resolves a cookie value to a live session and slides the idle window.
     *
     * Returns `null` for unknown, revoked and expired alike — the caller has no legitimate use
     * for the distinction, and reporting it would help an attacker probe for valid handles.
     */
    suspend fun resolve(cookieValue: String, now: Instant): Session? {
        val session = sessions.findByHash(tokenHasher.hash(cookieValue)) ?: return null
        if (!session.isActive(now)) return null

        // Only write when the slide is meaningful, so an active tab does not produce an UPDATE
        // per request.
        if (java.time.Duration.between(session.lastSeenAt, now) > TOUCH_INTERVAL) {
            sessions.touch(session.id, now, now.plus(lifetimes.sessionIdle))
        }
        return session
    }

    /**
     * Whether this device has been seen on this account before.
     *
     * Deliberately coarse — a hash of user agent plus IP. It drives a "new sign-in" notification
     * and nothing more; treating it as a security control would be unwise, since both inputs
     * are attacker-supplied.
     */
    suspend fun isNewDevice(userId: UserId, context: FlowContext, now: Instant): Boolean {
        val fingerprint = context.userAgent?.let(FlowRunner::hashForAudit) ?: return false
        return sessions.listActiveForUser(userId, now).none { it.userAgentHash == fingerprint }
    }

    private companion object {
        val TOUCH_INTERVAL: java.time.Duration = java.time.Duration.ofMinutes(5)
    }
}

/**
 * A human-readable device name for the session and trusted-device lists.
 *
 * Purely cosmetic. The user agent is attacker-supplied, so nothing may branch on this — it
 * exists so that "revoke the one that says iPhone" is a decision a person can make.
 */
internal fun describeDevice(userAgent: String): String {
    val platform = when {
        userAgent.contains("Windows", ignoreCase = true) -> "Windows"
        userAgent.contains("Macintosh", ignoreCase = true) -> "macOS"
        userAgent.contains("iPhone", ignoreCase = true) -> "iPhone"
        userAgent.contains("iPad", ignoreCase = true) -> "iPad"
        userAgent.contains("Android", ignoreCase = true) -> "Android"
        userAgent.contains("Linux", ignoreCase = true) -> "Linux"
        else -> "Unknown device"
    }
    val browser = when {
        userAgent.contains("Edg/", ignoreCase = true) -> "Edge"
        userAgent.contains("OPR/", ignoreCase = true) -> "Opera"
        userAgent.contains("Firefox", ignoreCase = true) -> "Firefox"
        userAgent.contains("Chrome", ignoreCase = true) -> "Chrome"
        userAgent.contains("Safari", ignoreCase = true) -> "Safari"
        else -> null
    }
    return listOfNotNull(platform, browser).joinToString(" · ").take(128)
}

/**
 * Mints, checks and rotates trusted-device tokens.
 *
 * The credential is 256 bits of randomness in a cookie; only its HMAC is stored, so this table
 * is not a list of devices an attacker can impersonate. Same construction as [SessionService],
 * deliberately — a trusted device is a long-lived bearer credential and gets the same treatment
 * the other long-lived ones get.
 *
 * What this service does *not* do is decide policy. Whether a device may skip MFA at all is the
 * login flow's call; this class only answers whether a presented token is currently good, and
 * hands back the successor.
 */
class TrustedDeviceService(
    private val devices: TrustedDeviceRepository,
    private val random: RandomSource,
    private val tokenHasher: TokenHasher,
    private val lifetimes: Lifetimes,
    private val transactionManager: TransactionManager,
    private val outbox: OutboxPort,
) {

    private val log = LoggerFactory.getLogger(TrustedDeviceService::class.java)

    /** Whether the deployment has the feature switched on at all. */
    val enabled: Boolean get() = !lifetimes.trustedDevice.isZero

    /**
     * Records a device as trusted.
     *
     * Only ever called after a second factor was actually verified — a token minted on the
     * strength of a password alone would make the first login on a new machine its own bypass.
     */
    suspend fun remember(
        userId: UserId,
        context: FlowContext,
        now: Instant,
    ): IssuedTrustedDevice? {
        if (!enabled) return null

        val plaintext = random.token(32)
        val device = TrustedDevice(
            id = TrustedDeviceId.random(),
            userId = userId,
            tokenHash = tokenHasher.hash(plaintext),
            previousTokenHash = null,
            label = context.userAgent?.let(::describeDevice),
            createdAt = now,
            lastUsedAt = now,
            expiresAt = now.plus(lifetimes.trustedDevice),
            revokedAt = null,
            revokedReason = null,
        )
        devices.insert(device)
        return IssuedTrustedDevice(device, plaintext)
    }

    /**
     * Checks a presented cookie and, on success, rotates it.
     *
     * Unknown, expired and revoked tokens all return [TrustedDeviceCheck.NotTrusted]. Telling
     * them apart would let an attacker holding a pile of stolen cookies learn which ones are
     * worth pursuing.
     *
     * The superseded generation is checked *before* concluding "not trusted", because a replay
     * of an old value is the one case that must not look like an ordinary unrecognised device.
     */
    suspend fun check(
        userId: UserId,
        presented: Secret?,
        context: FlowContext,
        now: Instant,
    ): TrustedDeviceCheck {
        if (!enabled) return TrustedDeviceCheck.NotTrusted
        val value = presented?.reveal()?.takeIf { it.isNotBlank() }
            ?: return TrustedDeviceCheck.NotTrusted
        val hash = tokenHasher.hash(value)

        val current = devices.findByHash(userId, hash)
        if (current != null) {
            if (!current.isActive(now)) return TrustedDeviceCheck.NotTrusted

            val successor = random.token(32)
            val successorHash = tokenHasher.hash(successor)
            val rotated = devices.rotate(
                id = current.id,
                expectedHash = hash,
                newHash = successorHash,
                at = now,
            )
            // Lost a race with a concurrent login, or the row was revoked in between. Either way
            // this request has no valid successor to hand out, so it must not skip the factor.
            if (!rotated) return TrustedDeviceCheck.NotTrusted

            return TrustedDeviceCheck.Trusted(
                IssuedTrustedDevice(
                    current.copy(
                        tokenHash = successorHash,
                        previousTokenHash = hash,
                        lastUsedAt = now,
                        label = current.label ?: context.userAgent?.let(::describeDevice),
                    ),
                    successor,
                ),
            )
        }

        devices.findByPreviousHash(userId, hash)?.let { superseded ->
            // Rotation hands out exactly one successor, so a second appearance of the old value
            // is not a race — the cookie was copied off the machine.
            revokeCompromisedDevice(superseded, hash, context, now)
            return TrustedDeviceCheck.Reused(superseded)
        }

        return TrustedDeviceCheck.NotTrusted
    }

    /**
     * Revokes a replayed device in its **own** transaction, and writes the notification there too.
     *
     * Both parts have to outlive the caller. Detecting reuse makes the login demand a second
     * factor, which the flow signals with a challenge — and a challenge unwinds the surrounding
     * transaction by design ([FlowRunner][dev.kamiql.helium.flow.FlowRunner]). Revoking inside
     * that transaction would hand the attacker a rollback of the very response to their theft.
     * Same reasoning, same mechanism as refresh-token reuse in the OAuth flows.
     */
    private suspend fun revokeCompromisedDevice(
        device: TrustedDevice,
        supersededHash: String,
        context: FlowContext,
        now: Instant,
    ) {
        runCatching {
            transactionManager.requiresNew {
                // The claim decides whether this call is the one that reports the incident.
                // Publishing unconditionally would let whoever holds the copied cookie generate
                // a security mail per attempt simply by re-sending it.
                val claimed = devices.claimReuse(device.userId, device.id, supersededHash, now)
                if (!claimed) return@requiresNew

                log.error(
                    "trusted device reuse detected for user {}; revoking device {}",
                    device.userId, device.id,
                )
                outbox.publish(
                    events = listOf(DomainEvent.TrustedDeviceReuseDetected(device.userId, device.id)),
                    context = OutboxContext(context.requestId, now),
                )
            }
        }.onFailure {
            // Must not mask the outcome: the caller still gets an ordinary MFA challenge, so a
            // failure here is silent to the attacker and has to be loud in the logs.
            log.error("FAILED to revoke reused trusted device {}; it may still be live", device.id, it)
        }
    }

    suspend fun list(userId: UserId, now: Instant): List<TrustedDevice> =
        devices.listActiveForUser(userId, now)

    suspend fun revoke(
        userId: UserId,
        id: TrustedDeviceId,
        now: Instant,
        reason: TrustedDeviceRevocationReason,
    ): Boolean = devices.revoke(userId, id, now, reason)

    suspend fun revokeAll(
        userId: UserId,
        now: Instant,
        reason: TrustedDeviceRevocationReason,
    ): Int = devices.revokeAllForUser(userId, now, reason)
}

/**
 * Issues and redeems one-time tokens for email verification, email change and password reset.
 *
 * All three share a shape: 256 bits of entropy, stored as an HMAC, single use, purpose-bound.
 */
class VerificationTokenService(
    private val tokens: VerificationTokenRepository,
    private val random: RandomSource,
    private val tokenHasher: TokenHasher,
    private val lifetimes: Lifetimes,
) {

    /** The plaintext token; it exists only long enough to be put in an outbox payload. */
    data class Issued(val id: VerificationTokenId, val plaintext: String)

    suspend fun issue(
        userId: UserId,
        purpose: VerificationPurpose,
        now: Instant,
        payload: String? = null,
    ): Issued {
        // Issuing a new token retires the old ones, so a leaked earlier link stops working the
        // moment the user asks for another (concept §2.6).
        tokens.invalidateAllForUser(userId, purpose, now)

        val plaintext = random.token(32)
        val record = StoredVerificationToken(
            id = VerificationTokenId.random(),
            userId = userId,
            tokenHash = tokenHasher.hash(plaintext),
            purpose = purpose,
            payload = payload,
            expiresAt = now.plus(lifetimeOf(purpose)),
            usedAt = null,
            createdAt = now,
        )
        tokens.insert(record)
        return Issued(record.id, plaintext)
    }

    /**
     * Atomically redeems a token.
     *
     * The `consume` call is a conditional UPDATE, so two requests presenting the same token
     * cannot both succeed.
     */
    suspend fun redeem(
        token: Secret,
        purpose: VerificationPurpose,
        now: Instant,
    ): StoredVerificationToken? {
        val hash = tokenHasher.hash(token.reveal())
        val record = tokens.findByHash(hash, purpose) ?: return null
        if (record.usedAt != null || !now.isBefore(record.expiresAt)) return null
        return if (tokens.consume(hash, purpose, now)) record else null
    }

    private fun lifetimeOf(purpose: VerificationPurpose) = when (purpose) {
        VerificationPurpose.EMAIL_VERIFICATION -> lifetimes.emailVerificationToken
        VerificationPurpose.EMAIL_CHANGE -> lifetimes.emailVerificationToken
        VerificationPurpose.PASSWORD_RESET -> lifetimes.passwordResetToken
    }
}

/**
 * Evaluates [PasswordPolicy].
 *
 * Length bounds and a breach check, deliberately no composition rules: forced symbol classes
 * push people toward predictable substitutions without adding entropy (concept §4.1).
 */
class PasswordPolicyService(
    private val policy: PasswordPolicy,
    private val breachedChecker: BreachedPasswordChecker,
) {

    suspend fun evaluate(
        password: Secret,
        username: Username? = null,
        email: EmailAddress? = null,
    ): PasswordPolicyResult {
        val reasons = mutableListOf<PasswordRejectionReason>()
        val length = password.reveal().length

        if (length < policy.minLength) reasons += PasswordRejectionReason.TOO_SHORT
        if (length > policy.maxLength) reasons += PasswordRejectionReason.TOO_LONG

        if (policy.rejectContainsIdentifier && reasons.isEmpty()) {
            val lowered = password.reveal().lowercase()
            val identifiers = listOfNotNull(
                username?.normalized,
                email?.normalized?.substringBefore('@'),
            ).filter { it.length >= 4 }
            if (identifiers.any { lowered.contains(it) }) {
                reasons += PasswordRejectionReason.CONTAINS_IDENTIFIER
            }
        }

        // Only consult the breach list once the cheap checks pass; it may be a network call.
        if (policy.rejectBreached && reasons.isEmpty() && breachedChecker.isBreached(password)) {
            reasons += PasswordRejectionReason.BREACHED
        }

        return if (reasons.isEmpty()) PasswordPolicyResult.Acceptable
        else PasswordPolicyResult.Rejected(reasons)
    }

    /** Shape the frontend renders as a live checklist during registration. */
    fun describe(): PasswordRequirements = PasswordRequirements(
        minLength = policy.minLength,
        maxLength = policy.maxLength,
        breachedCheck = policy.rejectBreached,
        rejectsIdentifier = policy.rejectContainsIdentifier,
    )
}

data class PasswordRequirements(
    val minLength: Int,
    val maxLength: Int,
    val breachedCheck: Boolean,
    val rejectsIdentifier: Boolean,
)
