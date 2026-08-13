package dev.kamiql.helium.domain.session

import dev.kamiql.helium.domain.common.TrustedDeviceId
import dev.kamiql.helium.domain.common.UserId
import java.time.Instant

/**
 * A device on which the user has already proven a second factor.
 *
 * Presenting the matching cookie lets the *next* password login skip the MFA challenge for
 * [expiresAt]. That is a real reduction in assurance, so the shape of this record is chosen to
 * keep the reduction bounded and observable:
 *
 *  * the cookie carries 256 bits of randomness and only `HMAC(pepper, value)` is stored, so a
 *    dump of this table is not a list of usable devices — the same treatment sessions, refresh
 *    tokens and verification tokens get;
 *  * it is bound to [userId], so a token minted for one account can never satisfy another;
 *  * [expiresAt] is absolute and never slides, unlike a session's idle window. A device that is
 *    trusted forever is a second factor that has been switched off, not deferred;
 *  * [previousTokenHash] keeps exactly one superseded generation so a copied cookie can be
 *    *detected* rather than merely rate-limited (see [TrustedDeviceRevocationReason.REUSE_DETECTED]).
 *
 * Deliberately **not** built on the coarse user-agent/IP fingerprint used for new-device
 * notifications: both of those inputs are attacker-supplied, which is fine for a notification
 * and disqualifying for a control.
 *
 * @param label human-readable device description for the account UI. Informative only — no
 *        security decision reads it, because it is derived from the user agent.
 */
data class TrustedDevice(
    val id: TrustedDeviceId,
    val userId: UserId,
    val tokenHash: String,
    val previousTokenHash: String?,
    val label: String?,
    val createdAt: Instant,
    val lastUsedAt: Instant,
    val expiresAt: Instant,
    val revokedAt: Instant?,
    val revokedReason: TrustedDeviceRevocationReason?,
) {
    fun isActive(now: Instant): Boolean = revokedAt == null && now.isBefore(expiresAt)
}

/**
 * A freshly minted device token together with its plaintext.
 *
 * Mirrors [IssuedSession]: the plaintext exists only in this object, is handed to the HTTP
 * boundary exactly once, and is never persisted.
 */
class IssuedTrustedDevice(
    val device: TrustedDevice,
    private val plaintext: String,
) {
    /** The value to place in the trusted-device cookie. Call once, at the HTTP boundary. */
    fun cookieValue(): String = plaintext

    override fun toString(): String = "IssuedTrustedDevice(${device.id}, redacted)"
}

/** Why a trusted device stopped being trusted. Recorded on the audit event. */
enum class TrustedDeviceRevocationReason {
    USER_REVOKED,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    MFA_CHANGED,
    ADMIN_ACTION,
    ACCOUNT_DELETED,

    /**
     * A superseded token was presented again, which means the cookie was copied: rotation gives
     * exactly one valid successor, so a second use of the old value cannot happen by accident.
     */
    REUSE_DETECTED,
}

/**
 * Outcome of presenting a trusted-device cookie during login.
 *
 * A sealed result rather than a nullable [TrustedDevice] because the three cases demand
 * genuinely different handling, and collapsing [Reused] into [NotTrusted] would silently turn a
 * detected cookie theft into an ordinary MFA prompt.
 */
sealed interface TrustedDeviceCheck {

    /** Skip the challenge. [rotated] is the successor token to hand back to the browser. */
    data class Trusted(val rotated: IssuedTrustedDevice) : TrustedDeviceCheck

    /**
     * The token was valid one generation ago. The device has been revoked; the caller must
     * still demand MFA and should raise a security notification.
     */
    data class Reused(val device: TrustedDevice) : TrustedDeviceCheck

    /**
     * No cookie, unknown, expired or revoked — all four collapse here on purpose. Telling them
     * apart would hand an attacker an oracle for which stolen cookies are worth replaying.
     */
    data object NotTrusted : TrustedDeviceCheck
}
