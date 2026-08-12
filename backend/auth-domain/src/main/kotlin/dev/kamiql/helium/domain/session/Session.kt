package dev.kamiql.helium.domain.session

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import java.time.Instant

/**
 * A browser session.
 *
 * The cookie carries a high-entropy random value; only `HMAC(pepper, value)` is stored, so a
 * database leak does not yield usable sessions. Two independent expiries are tracked, per
 * concept §4.2: an idle timeout that slides on use and an absolute timeout that never does.
 */
data class Session(
    val id: SessionId,
    val userId: UserId,
    /** Present when the session was created through a specific first-party client. */
    val clientId: ClientId?,
    val createdAt: Instant,
    val lastSeenAt: Instant,
    val idleExpiresAt: Instant,
    val absoluteExpiresAt: Instant,
    val revokedAt: Instant?,
    /**
     * Timestamp of the most recent *full* credential presentation. Step-up requirements
     * ([ReauthenticatedWithin][dev.kamiql.helium.flow.requirement]) compare against this, not
     * against [createdAt] — a week-old session must not be able to change a password.
     */
    val authenticatedAt: Instant,
    /** Truthful record of how the user proved identity, mirrored into the `amr` JWT claim. */
    val authenticationMethods: Set<AuthenticationMethod>,
    val ipHash: String?,
    val userAgentHash: String?,
    /** Human-readable device label derived from the user agent, for the session list UI. */
    val deviceLabel: String?,
) {
    fun isActive(now: Instant): Boolean =
        revokedAt == null && now.isBefore(idleExpiresAt) && now.isBefore(absoluteExpiresAt)

    /** True when MFA was actually satisfied for this session, not merely configured. */
    val mfaSatisfied: Boolean
        get() = authenticationMethods.any { it.isSecondFactor }

    fun reauthenticatedWithin(now: Instant, window: java.time.Duration): Boolean =
        !authenticatedAt.plus(window).isBefore(now)
}

/**
 * Authentication method reference values, aligned with RFC 8176 where one exists.
 *
 * Emitted in the `amr` claim so downstream services can make their own step-up decisions.
 */
enum class AuthenticationMethod(val amr: String, val isSecondFactor: Boolean) {
    PASSWORD("pwd", false),
    EXTERNAL_PROVIDER("federated", false),
    /** Directory bind through a [CredentialSource]; reserved for the LDAP adapter. */
    DIRECTORY("pwd", false),
    TOTP("otp", true),
    RECOVERY_CODE("rba", true),
    PASSKEY("swk", true),
    ;

    companion object {
        fun fromAmr(value: String): AuthenticationMethod? = entries.firstOrNull { it.amr == value }
    }
}

/**
 * A session together with the freshly minted cookie value.
 *
 * The plaintext exists only in this object, is returned exactly once, and is never persisted.
 */
class IssuedSession(
    val session: Session,
    private val plaintext: String,
) {
    /** The value to place in the session cookie. Call once, at the HTTP boundary. */
    fun cookieValue(): String = plaintext

    override fun toString(): String = "IssuedSession(${session.id}, redacted)"
}

/** Reason recorded on the audit event when a session ends. */
enum class SessionRevocationReason {
    USER_LOGOUT,
    USER_REVOKED_DEVICE,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    EMAIL_CHANGED,
    MFA_CHANGED,
    ADMIN_ACTION,
    RISK_DETECTED,
    ACCOUNT_DELETED,
    TOKEN_REUSE_DETECTED,
}
