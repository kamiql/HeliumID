package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.session.IssuedSession
import dev.kamiql.helium.domain.user.UserStatus

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
)

data class CompleteMfaCommand(
    val transactionId: TransactionId,
    val method: MfaType,
    val code: Secret,
)

data class LogoutCommand(val sessionId: SessionId)

data class RevokeSessionCommand(val sessionId: SessionId)

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

data object RegenerateRecoveryCodesCommand

data class RecoveryCodesGenerated(val codes: List<String>)

// --- provider linking ---------------------------------------------------------

data class UnlinkProviderCommand(val provider: ProviderKey)

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
