package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
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
import dev.kamiql.helium.domain.repository.VerificationTokenRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.IssuedSession
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.FlowRunner
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

    private fun describeDevice(userAgent: String): String {
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

    private companion object {
        val TOUCH_INTERVAL: java.time.Duration = java.time.Duration.ofMinutes(5)
    }
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
