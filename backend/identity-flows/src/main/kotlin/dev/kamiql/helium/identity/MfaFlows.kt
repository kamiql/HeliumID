package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.credential.PasswordHasher
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
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
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.requirement.Authenticated
import dev.kamiql.helium.flow.requirement.ReauthenticatedWithin
import dev.kamiql.helium.flow.step
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.MfaMethodRegistry
import dev.kamiql.helium.spi.RecoveryCodeIssuer

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
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
) {

    private val challengeKey = FlowStateKey<EnrollmentChallenge>("totp_enrollment", sensitive = true)
    private val codesKey = FlowStateKey<List<String>>("recovery_codes", sensitive = true)
    private val userIdKey = FlowStateKey<dev.kamiql.helium.domain.common.UserId>("user_id")

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

                    state[userIdKey] = userId
                    state[challengeKey] = method.beginEnrollment(userId, context.now)
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
                        response = MfaResponse(command.code),
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

            effect(
                effect("mfa-disabled") { _, _, state ->
                    listOf(DomainEvent.MfaDisabled(state.require(userIdKey), MfaType.TOTP))
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

            step(
                step("regenerate") { _, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    state[userIdKey] = userId
                    state[codesKey] = recoveryCodes.generate(userId, context.now)
                    StepResult.Continue
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
