package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.credential.PasswordHasher
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.userIdOrNull
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.PasswordCredentialRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowStateKey
import dev.kamiql.helium.flow.StepResult
import dev.kamiql.helium.flow.TransactionPolicy
import dev.kamiql.helium.flow.commitAction
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimiter
import dev.kamiql.helium.flow.requirement.Authenticated
import dev.kamiql.helium.flow.requirement.RateLimited
import dev.kamiql.helium.flow.requirement.ReauthenticatedWithin
import dev.kamiql.helium.flow.step
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.MfaMethodRegistry
import dev.kamiql.helium.spi.RecoveryCodeIssuer

/**
 * Longest factor label accepted.
 *
 * Mirrors the storage bound. Duplicated as a number rather than read from the schema because the
 * domain does not depend on persistence — the cost of that boundary is this one constant, and a
 * migration that widens the column simply makes this stricter than it needs to be, which fails
 * safely.
 */
private const val MAX_FACTOR_LABEL_LENGTH = 64

/**
 * MFA enrollment and management.
 *
 * Every one of these operations is on concept §4.10's step-up list, so they all require a
 * recent reauthentication. Enrolling *or removing* a factor is exactly what an attacker who
 * has stolen a live session would try first.
 */
class MfaFlows(
    private val users: UserRepository,
    private val credentials: PasswordCredentialRepository,
    private val sessions: SessionRepository,
    private val mfaRepository: MfaRepository,
    private val mfaMethods: MfaMethodRegistry,
    private val recoveryCodes: RecoveryCodeIssuer,
    private val passwordHasher: PasswordHasher,
    private val rateLimiter: RateLimiter,
    private val trustedDevices: TrustedDeviceService,
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
) {

    private val challengeKey = FlowStateKey<EnrollmentChallenge.Totp>("totp_enrollment", sensitive = true)
    private val webauthnChallengeKey =
        FlowStateKey<EnrollmentChallenge.WebAuthn>("webauthn_enrollment", sensitive = true)
    private val codesKey = FlowStateKey<List<String>>("recovery_codes", sensitive = true)
    private val userIdKey = FlowStateKey<UserId>("user_id")
    private val factorIdKey = FlowStateKey<MfaFactorId>("factor_id")

    /**
     * Per-account limit for a factor-management operation.
     *
     * Every flow here is behind [Authenticated], so the actor's id is the honest discriminator:
     * limiting by IP alone would let one stolen session hide behind a proxy pool, and would let
     * one abusive account throttle everybody sharing its egress address. The requirement is
     * declared *after* the authentication and reauthentication checks so that a caller who
     * cannot pass those never consumes another account's permits.
     *
     * [RateLimit.TOTP_VERIFY] is borrowed because it is the closest existing MFA-shaped budget;
     * a dedicated `MFA_MANAGE` constant belongs in `flow-engine`'s [RateLimit] companion.
     */
    private fun <C : Any> managementLimit(dimension: String): RateLimited<C> =
        RateLimited(dimension, RateLimit.TOTP_VERIFY, rateLimiter) { _, context ->
            context.actor.userIdOrNull?.value?.toString() ?: context.ipAddress
        }

    /**
     * Starts TOTP enrollment.
     *
     * The factor is created `PENDING`; it does not count towards MFA policy and cannot satisfy
     * a login challenge until [confirmTotpEnrollment] proves the user has the secret.
     */
    val beginTotpEnrollment: Flow<BeginTotpEnrollmentCommand, TotpEnrollmentStarted> =
        flow(FlowId("account.mfa.totp.begin")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_MFA_MANAGE)
            require(managementLimit("mfa.totp.begin"))

            step(
                step("begin-enrollment") { _, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val method = mfaMethods[MfaType.TOTP]
                        ?: return@step StepResult.Fail(AuthError.TemporarilyUnavailable)

                    if (method.isEnrolled(userId)) {
                        // Re-enrolling silently would orphan the existing authenticator without
                        // telling the user. Make them remove the old factor deliberately.
                        return@step StepResult.Fail(AuthError.Conflict)
                    }

                    // The registry is keyed by type, so anything but a TOTP challenge here means
                    // the server is misconfigured — not something the caller can fix by retrying
                    // differently.
                    val challenge = method.beginEnrollment(userId, context.now) as? EnrollmentChallenge.Totp
                        ?: return@step StepResult.Fail(AuthError.TemporarilyUnavailable)

                    state[userIdKey] = userId
                    state[challengeKey] = challenge
                    StepResult.Continue
                },
            )

            result { state ->
                val challenge = state.require(challengeKey)
                TotpEnrollmentStarted(
                    factorId = challenge.factorId,
                    secret = challenge.secret,
                    otpauthUri = challenge.provisioningUri,
                )
            }
        }

    /**
     * Confirms enrollment with a live code and issues recovery codes.
     *
     * The codes are returned exactly once, here. There is no endpoint that can show them
     * again — only regeneration, which invalidates the previous set.
     */
    val confirmTotpEnrollment: Flow<ConfirmTotpEnrollmentCommand, TotpEnrollmentConfirmed> =
        flow(FlowId("account.mfa.totp.confirm")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_MFA_MANAGE)
            // Confirmation takes a live code, so without a limit this is a six-digit oracle
            // that an authenticated attacker can hammer against a factor they just created.
            require(managementLimit("mfa.totp.confirm"))

            step(
                step("confirm") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    val factor = mfaRepository.findFactor(command.factorId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)
                    // Ownership check: a factor id from another account must not be activatable.
                    if (factor.userId != userId) return@step StepResult.Fail(AuthError.NotFound)

                    val method = mfaMethods[MfaType.TOTP]
                        ?: return@step StepResult.Fail(AuthError.TemporarilyUnavailable)

                    val confirmed = method.confirmEnrollment(
                        factorId = command.factorId,
                        response = MfaResponse.Code(command.code),
                        now = context.now,
                    )
                    if (!confirmed) return@step StepResult.Fail(AuthError.MfaInvalid)

                    state[userIdKey] = userId
                    state[codesKey] = recoveryCodes.generate(userId, context.now)
                    StepResult.Continue
                },
            )

            effect(
                effect("mfa-enrolled") { _, _, state ->
                    listOf(DomainEvent.MfaEnrolled(state.require(userIdKey), MfaType.TOTP))
                },
            )

            result { state -> TotpEnrollmentConfirmed(state.require(codesKey)) }
        }

    /**
     * Removes a TOTP factor.
     *
     * Requires the current password on top of a recent reauthentication. Disabling MFA is the
     * single most valuable action for someone holding a stolen session, so it is the most
     * heavily gated (concept §4.10).
     */
    val disableTotp: Flow<DisableTotpCommand, Unit> =
        flow(FlowId("account.mfa.totp.disable")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_MFA_MANAGE)
            // The password check below is the second brute-force surface in this class.
            require(managementLimit("mfa.totp.disable"))

            step(
                step("verify-and-revoke") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    val credential = credentials.findByUserId(userId)
                    if (credential != null) {
                        val supplied = command.currentPassword
                            ?: return@step StepResult.Fail(AuthError.InvalidCredentials)
                        if (!passwordHasher.verify(supplied, credential.hash)) {
                            return@step StepResult.Fail(AuthError.InvalidCredentials)
                        }
                    }

                    val factor = mfaRepository.findFactor(command.factorId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)
                    if (factor.userId != userId) return@step StepResult.Fail(AuthError.NotFound)

                    mfaRepository.revokeFactor(command.factorId, context.now)
                    state[userIdKey] = userId
                    StepResult.Continue
                },
            )

            commitAction(
                commitAction("revoke-trusted-devices") { _, context, state ->
                    // Trusted devices are exemptions from *this* factor. Leaving them alive after
                    // it is removed would mean a re-enrolled TOTP is not asked for on any machine
                    // that was trusted under the old one.
                    trustedDevices.revokeAll(
                        state.require(userIdKey), context.now, TrustedDeviceRevocationReason.MFA_CHANGED,
                    )
                },
            )

            effect(
                effect("mfa-disabled") { _, _, state ->
                    listOf(DomainEvent.MfaDisabled(state.require(userIdKey), MfaType.TOTP))
                },
            )

            result { }
        }

    // =========================================================================
    // WebAuthn / passkeys
    // =========================================================================

    /**
     * Starts passkey enrollment.
     *
     * Unlike [beginTotpEnrollment] this does **not** refuse when the user already has a factor.
     * Several authenticators per account is the point of passkeys — a phone and a hardware key,
     * or a work laptop and a home one — and the whole recovery story rests on the user being
     * able to register a second one before they lose the first.
     *
     * Nothing secret is produced here: the key pair is generated on the authenticator and only
     * the public half ever comes back, so unlike TOTP there is no secret to leak in the
     * response.
     */
    val beginWebAuthnEnrollment: Flow<BeginWebAuthnEnrollmentCommand, WebAuthnEnrollmentStarted> =
        flow(FlowId("account.mfa.webauthn.begin")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_MFA_MANAGE)
            // Every call writes a PENDING factor row and a challenge. Unlimited, it is a way to
            // fill the factor table and the challenge store on someone else's behalf.
            require(managementLimit("mfa.webauthn.begin"))

            step(
                step("begin-enrollment") { _, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val method = mfaMethods[MfaType.WEBAUTHN]
                        ?: return@step StepResult.Fail(AuthError.TemporarilyUnavailable)

                    // The registry is keyed by type, so anything but a WebAuthn challenge here
                    // means the server is misconfigured — not something the caller can fix by
                    // retrying differently.
                    val challenge = method.beginEnrollment(userId, context.now) as? EnrollmentChallenge.WebAuthn
                        ?: return@step StepResult.Fail(AuthError.TemporarilyUnavailable)

                    state[userIdKey] = userId
                    state[webauthnChallengeKey] = challenge
                    StepResult.Continue
                },
            )

            result { state ->
                val challenge = state.require(webauthnChallengeKey)
                WebAuthnEnrollmentStarted(
                    factorId = challenge.factorId,
                    options = challenge.options,
                )
            }
        }

    /**
     * Activates a passkey from the authenticator's registration response.
     *
     * Recovery codes are issued only when the user has none. Regenerating on every enrollment
     * would silently invalidate the sheet a user with an existing factor already wrote down and
     * filed — the failure mode of which is discovered at the worst possible moment, when they
     * have lost the factor and reach for the codes.
     */
    val confirmWebAuthnEnrollment: Flow<ConfirmWebAuthnEnrollmentCommand, WebAuthnEnrollmentConfirmed> =
        flow(FlowId("account.mfa.webauthn.confirm")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_MFA_MANAGE)
            require(managementLimit("mfa.webauthn.confirm"))

            step(
                step("confirm") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    // Checked before anything is written. Storage bounds the label, and finding
                    // that out after the passkey is active would leave the user with a working
                    // factor and a failed request — the one combination they cannot act on.
                    // A blank label is not an error; it just means "keep the default".
                    val label = command.label?.trim()?.takeIf { it.isNotEmpty() }
                    if (label != null && label.length > MAX_FACTOR_LABEL_LENGTH) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("label" to "too_long")),
                        )
                    }

                    val factor = mfaRepository.findFactor(command.factorId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)
                    // Ownership check: a factor id from another account must not be activatable.
                    // Wrong owner and wrong type answer identically to "no such factor", so the
                    // endpoint never confirms that an id exists.
                    if (factor.userId != userId) return@step StepResult.Fail(AuthError.NotFound)
                    if (factor.type != MfaType.WEBAUTHN) return@step StepResult.Fail(AuthError.NotFound)

                    val method = mfaMethods[MfaType.WEBAUTHN]
                        ?: return@step StepResult.Fail(AuthError.TemporarilyUnavailable)

                    val confirmed = method.confirmEnrollment(
                        factorId = command.factorId,
                        response = command.response,
                        now = context.now,
                    )
                    if (!confirmed) return@step StepResult.Fail(AuthError.MfaInvalid)

                    // Applied only after the authenticator's response verified, so a rejected
                    // attestation cannot rename someone's factor as a side effect.
                    if (label != null) mfaRepository.relabelFactor(command.factorId, label)

                    state[userIdKey] = userId
                    state[factorIdKey] = command.factorId
                    // First factor only. `remaining` counts unused codes, so a user who has
                    // spent every code they were given is treated as having none — which is the
                    // right reading: there is nothing left to invalidate.
                    if (recoveryCodes.remaining(userId) == 0) {
                        state[codesKey] = recoveryCodes.generate(userId, context.now)
                    }
                    StepResult.Continue
                },
            )

            effect(
                effect("mfa-enrolled") { _, _, state ->
                    listOf(DomainEvent.MfaEnrolled(state.require(userIdKey), MfaType.WEBAUTHN))
                },
            )

            result { state ->
                WebAuthnEnrollmentConfirmed(
                    factorId = state.require(factorIdKey),
                    recoveryCodes = state[codesKey],
                )
            }
        }

    /**
     * Removes a passkey.
     *
     * Gated on the current password on top of a recent reauthentication, for the same reason
     * [disableTotp] is: removing a factor is the single most valuable action for someone holding
     * a stolen session (concept §4.10).
     */
    val removeWebAuthnCredential: Flow<RemoveWebAuthnCredentialCommand, Unit> =
        flow(FlowId("account.mfa.webauthn.remove")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_MFA_MANAGE)
            require(managementLimit("mfa.webauthn.remove"))

            step(
                step("verify-and-revoke") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    val credential = credentials.findByUserId(userId)
                    if (credential != null) {
                        val supplied = command.currentPassword
                            ?: return@step StepResult.Fail(AuthError.InvalidCredentials)
                        if (!passwordHasher.verify(supplied, credential.hash)) {
                            return@step StepResult.Fail(AuthError.InvalidCredentials)
                        }
                    }

                    val factor = mfaRepository.findFactor(command.factorId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)
                    if (factor.userId != userId) return@step StepResult.Fail(AuthError.NotFound)
                    if (factor.type != MfaType.WEBAUTHN) return@step StepResult.Fail(AuthError.NotFound)

                    mfaRepository.revokeFactor(command.factorId, context.now)
                    state[userIdKey] = userId
                    StepResult.Continue
                },
            )

            commitAction(
                commitAction("revoke-trusted-devices") { _, context, state ->
                    // Trusted devices are exemptions from *this* factor. Leaving them alive after
                    // it is removed would mean a re-enrolled passkey is not asked for on any
                    // machine that was trusted under the old one.
                    trustedDevices.revokeAll(
                        state.require(userIdKey), context.now, TrustedDeviceRevocationReason.MFA_CHANGED,
                    )
                },
            )

            effect(
                effect("mfa-disabled") { _, _, state ->
                    listOf(DomainEvent.MfaDisabled(state.require(userIdKey), MfaType.WEBAUTHN))
                },
            )

            result { }
        }

    /** Replaces the recovery-code set. The previous codes stop working immediately. */
    val regenerateRecoveryCodes: Flow<RegenerateRecoveryCodesCommand, RecoveryCodesGenerated> =
        flow(FlowId("account.mfa.recovery-codes.regenerate")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_MFA_MANAGE)
            // Each call invalidates the previous set and revokes every trusted device, so a
            // loop over it is a denial-of-service against the account owner.
            require(managementLimit("mfa.recovery-codes.regenerate"))

            step(
                step("regenerate") { _, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    state[userIdKey] = userId
                    state[codesKey] = recoveryCodes.generate(userId, context.now)
                    StepResult.Continue
                },
            )

            commitAction(
                commitAction("revoke-trusted-devices") { _, context, state ->
                    // Regenerating recovery codes is what someone does after losing a factor or
                    // suspecting the old codes leaked. Both readings argue for dropping the
                    // machines that were allowed to skip the factor entirely.
                    trustedDevices.revokeAll(
                        state.require(userIdKey), context.now, TrustedDeviceRevocationReason.MFA_CHANGED,
                    )
                },
            )

            effect(
                effect("recovery-codes-regenerated") { _, _, state ->
                    listOf(DomainEvent.RecoveryCodesRegenerated(state.require(userIdKey)))
                },
            )

            result { state -> RecoveryCodesGenerated(state.require(codesKey)) }
        }
}
