package dev.kamiql.helium.domain.policy

import java.time.Duration

/**
 * Every credential lifetime in one place, with the concept §4.2 defaults.
 *
 * Centralised so that a security review can read the whole timing policy in one screen, and so
 * that tests can shorten everything without reaching into individual flows.
 */
data class Lifetimes(
    val authorizationCode: Duration = Duration.ofSeconds(60),
    val accessToken: Duration = Duration.ofMinutes(5),
    val idToken: Duration = Duration.ofMinutes(5),
    val sessionIdle: Duration = Duration.ofHours(12),
    val sessionAbsolute: Duration = Duration.ofDays(7),
    val refreshTokenInactivity: Duration = Duration.ofDays(30),
    val refreshTokenAbsolute: Duration = Duration.ofDays(90),
    val mfaTransaction: Duration = Duration.ofMinutes(5),
    val emailVerificationToken: Duration = Duration.ofHours(24),
    val passwordResetToken: Duration = Duration.ofMinutes(15),
    val oauthState: Duration = Duration.ofMinutes(10),
    val providerLinkTransaction: Duration = Duration.ofMinutes(10),
    val consentTransaction: Duration = Duration.ofMinutes(10),
    /**
     * How recently the user must have proved their identity before a step-up operation.
     * Concept §8.2 uses five minutes for password change.
     */
    val reauthenticationWindow: Duration = Duration.ofMinutes(5),
    /** How long a completed idempotent response is replayable. */
    val idempotencyRecord: Duration = Duration.ofHours(24),
) {
    init {
        require(refreshTokenInactivity <= refreshTokenAbsolute) {
            "refresh inactivity timeout must not exceed the absolute timeout"
        }
        require(sessionIdle <= sessionAbsolute) {
            "session idle timeout must not exceed the absolute timeout"
        }
        require(accessToken <= Duration.ofMinutes(15)) {
            "access tokens are only revocable by expiry; keep them short"
        }
    }

    companion object {
        val DEFAULT: Lifetimes = Lifetimes()
    }
}
