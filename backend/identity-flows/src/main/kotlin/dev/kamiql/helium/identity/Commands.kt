package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.TrustedDeviceId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions
import dev.kamiql.helium.domain.mfa.WebAuthnRegistrationOptions
import dev.kamiql.helium.domain.session.IssuedSession
import dev.kamiql.helium.domain.session.IssuedTrustedDevice
import dev.kamiql.helium.domain.user.UserStatus
import java.time.Instant

/**
 * Commands and results for the identity flows.
 *
 * Commands carry raw user input; validation happens inside the flow, not at the route, so the
 * same rules apply no matter which transport invoked it. Anything secret is a
 * [Secret] so it cannot be logged by an accidental `toString()` on the command.
 */

data class RegisterCommand(
    val username: String,
    val email: String,
    val password: Secret,
    val firstName: String,
    val lastName: String,
)

/**
 * Registration always reports the same thing.
 *
 * There is no `userId`, no "already exists" and no distinguishing status: the response for a
 * fresh address and for one that is already registered must be byte-identical, or registration
 * becomes an account-enumeration oracle (concept §2.6).
 */
data object RegisterAccepted

data class VerifyEmailCommand(val token: Secret)

data class ResendVerificationCommand(val email: String)

data class LoginCommand(
    /** Username or email; resolved through a single normalized lookup. */
    val identifier: String,
    val password: Secret,
    /**
     * Value of the trusted-device cookie, if the browser sent one.
     *
     * Read from the request by the route and passed in as opaque input — the flow decides what
     * it means. An absent, unknown or stale value is not an error and produces the ordinary MFA
     * challenge.
     */
    val trustedDeviceToken: Secret? = null,
)

/**
 * Login either completes or hands back a challenge.
 *
 * [FlowResult.Challenge][dev.kamiql.helium.flow.FlowResult.Challenge] covers the MFA case, so
 * this type only describes success.
 */
data class LoginSucceeded(
    val session: IssuedSession,
    val userId: UserId,
    val newDevice: Boolean,
    /** What the HTTP layer should do with the trusted-device cookie. */
    val trustedDevice: TrustedDeviceDirective = TrustedDeviceDirective.Keep,
)

/**
 * Instruction to the HTTP boundary about the trusted-device cookie.
 *
 * A sealed type rather than a nullable token because "issue this value", "delete what you have"
 * and "leave it alone" are three different outcomes, and a `null` would collapse the last two
 * into one — leaving a revoked device's cookie sitting in the browser.
 */
sealed interface TrustedDeviceDirective {

    /** Set the cookie to [device]'s plaintext, valid until [expiresAt]. */
    data class Issue(val device: IssuedTrustedDevice, val expiresAt: Instant) : TrustedDeviceDirective

    /** Delete the cookie: the device it referred to is gone. */
    data object Clear : TrustedDeviceDirective

    /** Touch nothing. */
    data object Keep : TrustedDeviceDirective
}

/**
 * Asks for the server-chosen nonce a method needs before it can be answered.
 *
 * Only meaningful for challenge-signing methods; for TOTP and recovery codes there is nothing
 * to hand out and the result carries no options. Reads the MFA transaction without consuming
 * it — spending it here would mean fetching a challenge burned the user's one attempt.
 */
data class BeginMfaChallengeCommand(
    val transactionId: TransactionId,
    val method: MfaType,
)

/** @param webauthnOptions `null` for methods that do not sign a challenge. */
data class MfaChallengeStarted(
    val method: MfaType,
    val webauthnOptions: WebAuthnAuthenticationOptions?,
)

data class CompleteMfaCommand(
    val transactionId: TransactionId,
    val method: MfaType,
    /**
     * What the user presented.
     *
     * Typed as the sealed [MfaResponse] rather than a bare code so a passkey assertion travels
     * the same path as a TOTP code instead of needing a parallel flow.
     */
    val response: MfaResponse,
    /**
     * User asked to skip the challenge on this device next time.
     *
     * Defaults to `false`: remembering a device lowers assurance, so it happens only on an
     * explicit request, never as a side effect of signing in.
     */
    val rememberDevice: Boolean = false,
)

/**
 * Re-proves identity for the session the caller already holds.
 *
 * Deliberately not a second [LoginCommand]. Signing in again mints a session, and the step-up
 * prompt fires on every sensitive confirmation — so replaying login turns a handful of ordinary
 * actions into a device list full of sessions the user never knowingly started. This refreshes
 * the existing one instead; no cookie is issued and no identifier is accepted, because which
 * account is being re-proved is settled by the session, not by the request body.
 */
data class ReauthenticateCommand(val password: Secret)

/**
 * Answers the second-factor challenge raised by a [ReauthenticateCommand].
 *
 * No `rememberDevice` counterpart to [CompleteMfaCommand]: the trusted-device exemption lowers
 * the bar for future *sign-ins*, and a step-up prompt is not the place to grant it.
 */
data class CompleteReauthenticationCommand(
    val transactionId: TransactionId,
    val method: MfaType,
    val response: MfaResponse,
)

data class LogoutCommand(val sessionId: SessionId)

data class RevokeSessionCommand(val sessionId: SessionId)

data class RevokeTrustedDeviceCommand(val deviceId: TrustedDeviceId)

data object RevokeAllTrustedDevicesCommand

/** @param revoked how many devices were still live when the sweep ran. */
data class TrustedDevicesRevoked(val revoked: Int)

data class RequestPasswordResetCommand(val email: String)

data class CompletePasswordResetCommand(
    val token: Secret,
    val newPassword: Secret,
)

data class ChangePasswordCommand(
    val currentPassword: Secret,
    val newPassword: Secret,
)

data class RequestEmailChangeCommand(
    val newEmail: String,
    val currentPassword: Secret,
)

data class ConfirmEmailChangeCommand(val token: Secret)

data class UpdateProfileCommand(
    val username: String?,
    val firstName: String?,
    val lastName: String?,
)

data class DeleteAccountCommand(val currentPassword: Secret?)

// --- MFA ---------------------------------------------------------------------

data object BeginTotpEnrollmentCommand

/**
 * The one and only time the TOTP secret leaves the server.
 *
 * @param secret base32 for manual entry.
 * @param otpauthUri the `otpauth://` URI the client renders as a QR code. The client renders
 *        it; the server does not generate an image, which keeps a barcode library — and the
 *        secret — out of the response pipeline.
 */
data class TotpEnrollmentStarted(
    val factorId: MfaFactorId,
    val secret: String,
    val otpauthUri: String,
)

data class ConfirmTotpEnrollmentCommand(
    val factorId: MfaFactorId,
    val code: Secret,
)

/** Recovery codes are returned once, at confirmation, and never again. */
data class TotpEnrollmentConfirmed(val recoveryCodes: List<String>)

data class DisableTotpCommand(
    val factorId: MfaFactorId,
    val currentPassword: Secret?,
)

/** @param label what the user calls this authenticator ("Yubikey", "iPhone"). */
data class BeginWebAuthnEnrollmentCommand(val label: String?)

/**
 * Creation options for `navigator.credentials.create()`.
 *
 * No secret leaves the server here, unlike TOTP: the key pair is generated on the
 * authenticator and only the public half ever comes back.
 */
data class WebAuthnEnrollmentStarted(
    val factorId: MfaFactorId,
    val options: WebAuthnRegistrationOptions,
)

data class ConfirmWebAuthnEnrollmentCommand(
    val factorId: MfaFactorId,
    val label: String?,
    val response: MfaResponse.WebAuthnRegistration,
)

/**
 * @param recoveryCodes issued only when this factor is the user's first, and `null` otherwise.
 *        Regenerating unconditionally would silently invalidate the codes a user with an
 *        existing factor already wrote down.
 */
data class WebAuthnEnrollmentConfirmed(
    val factorId: MfaFactorId,
    val recoveryCodes: List<String>?,
)

data class RemoveWebAuthnCredentialCommand(
    val factorId: MfaFactorId,
    val currentPassword: Secret?,
)

data object RegenerateRecoveryCodesCommand

data class RecoveryCodesGenerated(val codes: List<String>)

// --- provider linking ---------------------------------------------------------

data class UnlinkProviderCommand(val provider: ProviderKey)

// --- authorized applications ------------------------------------------------------

/** Cuts one OAuth client off from the caller's account. */
data class RevokeAuthorizationCommand(val clientId: ClientId)

// --- administration -------------------------------------------------------------

data class AdminUpdateUserStatusCommand(
    val userId: UserId,
    val status: UserStatus,
)

data class AdminAssignRolesCommand(
    val userId: UserId,
    val roles: Set<String>,
)

data class AdminRevokeUserSessionsCommand(val userId: UserId)
