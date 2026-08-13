package dev.kamiql.helium.domain.event

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.TrustedDeviceId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import java.time.Instant

/**
 * Something that happened, stated in past tense.
 *
 * Events are written to the outbox **inside** the transaction that caused them and delivered
 * after commit (concept §2.4). They therefore carry only identifiers and enum values — no
 * secrets, no tokens, no raw provider payloads — because they are serialized to a durable
 * table and to external systems.
 */
sealed interface DomainEvent {

    /** Stable dotted name, also used as the outbox `event_type`. */
    val type: String

    /** Subject of the event; drives per-user notification fan-out. */
    val userId: UserId?

    // --- account lifecycle --------------------------------------------------

    data class UserRegistered(override val userId: UserId) : DomainEvent {
        override val type = "user.registered"
    }

    data class EmailVerificationRequested(
        override val userId: UserId,
        /** Delivered to the address being verified, which may not be the primary one yet. */
        val tokenId: String,
        val purpose: VerificationPurpose,
    ) : DomainEvent {
        override val type = "user.email-verification-requested"
    }

    data class EmailVerified(override val userId: UserId) : DomainEvent {
        override val type = "user.email-verified"
    }

    data class EmailChanged(
        override val userId: UserId,
        /** Both addresses are notified: the new one to confirm, the old one to warn (§2.6). */
        val previousEmailNormalized: String,
    ) : DomainEvent {
        override val type = "user.email-changed"
    }

    data class PasswordChanged(override val userId: UserId) : DomainEvent {
        override val type = "user.password-changed"
    }

    data class PasswordResetRequested(
        override val userId: UserId,
        val tokenId: String,
    ) : DomainEvent {
        override val type = "user.password-reset-requested"
    }

    data class PasswordResetCompleted(override val userId: UserId) : DomainEvent {
        override val type = "user.password-reset-completed"
    }

    data class AccountStatusChanged(
        override val userId: UserId,
        val newStatus: String,
        val actorUserId: UserId?,
    ) : DomainEvent {
        override val type = "user.status-changed"
    }

    data class AccountDeleted(override val userId: UserId) : DomainEvent {
        override val type = "user.deleted"
    }

    // --- authentication -----------------------------------------------------

    data class LoginSucceeded(
        override val userId: UserId,
        val sessionId: SessionId?,
        val clientId: ClientId?,
        /** True when the device fingerprint has not been seen for this account before. */
        val newDevice: Boolean,
    ) : DomainEvent {
        override val type = "auth.login-succeeded"
    }

    data class LoginFailed(
        override val userId: UserId?,
        val reason: String,
    ) : DomainEvent {
        override val type = "auth.login-failed"
    }

    /**
     * A live session re-proved identity for a step-up operation.
     *
     * Kept apart from [LoginSucceeded] rather than folded into it, because the two answer
     * different questions. A login says a session came into existence; this says an existing one
     * was refreshed immediately before something account-takeover-sensitive happened. Reading a
     * password change or an MFA removal in the audit log means reading the step-up that preceded
     * it, and that row has to exist on its own.
     *
     * Notably *not* mailed to the user: unlike a sign-in from a new device, a step-up is
     * something the account owner is doing right now in the tab in front of them.
     */
    data class Reauthenticated(
        override val userId: UserId,
        val sessionId: SessionId,
        /** True when a second factor was presented, and not merely enrolled. */
        val mfa: Boolean,
    ) : DomainEvent {
        override val type = "auth.reauthenticated"
    }

    data class SessionRevoked(
        override val userId: UserId,
        val sessionId: SessionId?,
        val reason: SessionRevocationReason,
        val count: Int,
    ) : DomainEvent {
        override val type = "auth.session-revoked"
    }

    // --- trusted devices ------------------------------------------------------

    /** The user asked to skip MFA on this device for the configured window. */
    data class TrustedDeviceAdded(
        override val userId: UserId,
        val deviceId: TrustedDeviceId,
        val expiresAt: Instant,
    ) : DomainEvent {
        override val type = "auth.trusted-device-added"
    }

    /** A login skipped the MFA challenge because the device was trusted. */
    data class TrustedDeviceUsed(
        override val userId: UserId,
        val deviceId: TrustedDeviceId,
    ) : DomainEvent {
        override val type = "auth.trusted-device-used"
    }

    data class TrustedDeviceRevoked(
        override val userId: UserId,
        val deviceId: TrustedDeviceId?,
        val reason: TrustedDeviceRevocationReason,
        val count: Int,
    ) : DomainEvent {
        override val type = "auth.trusted-device-revoked"
    }

    /**
     * A superseded device cookie was presented again — the value was copied off the machine.
     * Ranks with [RefreshTokenReuseDetected]: the device is revoked and the owner is told.
     */
    data class TrustedDeviceReuseDetected(
        override val userId: UserId,
        val deviceId: TrustedDeviceId,
    ) : DomainEvent {
        override val type = "auth.trusted-device-reuse-detected"
    }

    // --- MFA ----------------------------------------------------------------

    data class MfaEnrolled(override val userId: UserId, val method: MfaType) : DomainEvent {
        override val type = "mfa.enrolled"
    }

    data class MfaDisabled(override val userId: UserId, val method: MfaType) : DomainEvent {
        override val type = "mfa.disabled"
    }

    data class RecoveryCodesRegenerated(override val userId: UserId) : DomainEvent {
        override val type = "mfa.recovery-codes-regenerated"
    }

    data class RecoveryCodeUsed(override val userId: UserId, val remaining: Int) : DomainEvent {
        override val type = "mfa.recovery-code-used"
    }

    // --- external identities -------------------------------------------------

    data class ProviderLinked(
        override val userId: UserId,
        val provider: ProviderKey,
    ) : DomainEvent {
        override val type = "identity.provider-linked"
    }

    data class ProviderUnlinked(
        override val userId: UserId,
        val provider: ProviderKey,
    ) : DomainEvent {
        override val type = "identity.provider-unlinked"
    }

    // --- tokens ---------------------------------------------------------------

    /**
     * The single most important security signal this system emits: a refresh token was
     * presented twice. Always notifies the account owner (concept §4.10).
     */
    data class RefreshTokenReuseDetected(
        override val userId: UserId,
        val clientId: ClientId,
    ) : DomainEvent {
        override val type = "token.refresh-reuse-detected"
    }

    /**
     * The account owner cut an application off from their account.
     *
     * Worth a permanent record even though it removes access rather than granting it: it is the
     * evidence that answers "why did this integration stop working", and a burst of these from
     * one account is a plausible sign that somebody else is cleaning up after a takeover.
     */
    data class AuthorizationRevoked(
        override val userId: UserId,
        val clientId: ClientId,
        /** Refresh-token families killed. Zero is ordinary — the client may hold no live tokens. */
        val revokedGrants: Int,
    ) : DomainEvent {
        override val type = "oauth.authorization-revoked"
    }

    // --- clients ---------------------------------------------------------------

    data class ClientRegistered(
        val clientId: ClientId,
        val actorUserId: UserId?,
    ) : DomainEvent {
        override val type = "client.registered"
        override val userId: UserId? get() = actorUserId
    }

    data class ClientSecretRotated(
        val clientId: ClientId,
        val actorUserId: UserId?,
    ) : DomainEvent {
        override val type = "client.secret-rotated"
        override val userId: UserId? get() = actorUserId
    }

    // --- scopes -----------------------------------------------------------------

    /**
     * A scope was created or its description changed.
     *
     * Worth auditing even though it grants nothing on its own: the consent screen shows the
     * description verbatim, so editing one silently changes what users believe they agreed to.
     */
    data class ScopeUpserted(
        val scope: String,
        val actorUserId: UserId?,
    ) : DomainEvent {
        override val type = "scope.upserted"
        override val userId: UserId? get() = actorUserId
    }

    data class ScopeDeleted(
        val scope: String,
        val actorUserId: UserId?,
    ) : DomainEvent {
        override val type = "scope.deleted"
        override val userId: UserId? get() = actorUserId
    }
}

/** Why a one-time token was issued. Keeps reset tokens from being usable for verification. */
enum class VerificationPurpose {
    EMAIL_VERIFICATION,
    EMAIL_CHANGE,
    PASSWORD_RESET,
    ;

    val token: String get() = name.lowercase()
}
