package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.Normalization
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.credential.PasswordHasher
import dev.kamiql.helium.domain.credential.PasswordPolicyResult
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.event.VerificationPurpose
import dev.kamiql.helium.domain.mfa.MfaPolicy
import dev.kamiql.helium.domain.mfa.MfaTransaction
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.policy.userIdOrNull
import dev.kamiql.helium.domain.repository.PasswordCredentialRepository
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.domain.repository.RoleRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.IssuedSession
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.flow.ChallengeDescriptor
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowStateKey
import dev.kamiql.helium.flow.IdempotencyPolicy
import dev.kamiql.helium.flow.StepResult
import dev.kamiql.helium.flow.TransactionPolicy
import dev.kamiql.helium.flow.commitAction
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimiter
import dev.kamiql.helium.flow.port.SecurityTransactionStore
import dev.kamiql.helium.flow.requirement.Authenticated
import dev.kamiql.helium.flow.requirement.EmailVerified
import dev.kamiql.helium.flow.requirement.RateLimited
import dev.kamiql.helium.flow.requirement.ReauthenticatedWithin
import dev.kamiql.helium.flow.requirement.Unauthenticated
import dev.kamiql.helium.flow.step
import dev.kamiql.helium.spi.MfaMethodRegistry
import org.slf4j.LoggerFactory

/**
 * The local identity flows.
 *
 * Every flow is a named declaration whose requirements are visible at the top. That is the
 * whole point of the engine: to answer "what must be true before this can happen?" by reading
 * one screen, rather than by tracing a route handler into three services.
 *
 * @param mfaPolicy when a second factor is demanded.
 */
class IdentityFlows(
    private val users: UserRepository,
    private val credentials: PasswordCredentialRepository,
    private val sessions: SessionRepository,
    private val roles: RoleRepository,
    private val refreshTokens: RefreshTokenRepository,
    private val passwordHasher: PasswordHasher,
    private val passwordPolicy: PasswordPolicyService,
    private val sessionService: SessionService,
    private val verificationTokens: VerificationTokenService,
    private val transactions: SecurityTransactionStore,
    private val mfaMethods: MfaMethodRegistry,
    private val rateLimiter: RateLimiter,
    private val random: RandomSource,
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
    private val mfaPolicy: MfaPolicy = MfaPolicy.OPTIONAL,
) {

    private val log = LoggerFactory.getLogger(IdentityFlows::class.java)

    // --- state keys -----------------------------------------------------------
    //
    // Declared next to the flows that use them so a find-usages shows every reader and writer.
    // `sensitive = true` keeps a value out of audit metadata and diagnostics.

    private val userKey = FlowStateKey<User>("user")
    private val issuedSessionKey = FlowStateKey<IssuedSession>("session", sensitive = true)
    private val newDeviceKey = FlowStateKey<Boolean>("new_device")
    private val verificationTokenKey =
        FlowStateKey<VerificationTokenService.Issued>("verification_token", sensitive = true)
    private val revokedCountKey = FlowStateKey<Int>("revoked_sessions")
    private val previousEmailKey = FlowStateKey<String>("previous_email")

    // =========================================================================
    // registration and email verification
    // =========================================================================

    /**
     * Registration.
     *
     * The response is identical whether the address was free or already taken, and the flow
     * still consumes the same rate-limit permits and does the same amount of work either way.
     * Concept §2.6: "Never reveal whether the email already exists."
     */
    val register: Flow<RegisterCommand, RegisterAccepted> =
        flow(FlowId("identity.register")) {
            transaction(TransactionPolicy.Required)
            idempotency(IdempotencyPolicy.Optional)
            auditAs("identity.register")

            require(Unauthenticated)
            require(
                RateLimited<RegisterCommand>("register.ip", RateLimit.REGISTRATION, rateLimiter) { _, context ->
                    context.ipAddress
                },
            )
            require(
                RateLimited<RegisterCommand>("register.email", RateLimit.REGISTRATION, rateLimiter) { command, _ ->
                    Normalization.fold(command.email)
                },
            )

            step(
                step("validate-input") { command, _, state ->
                    val username = Username.parse(command.username)
                    val email = EmailAddress.parse(command.email)
                    val fields = buildMap {
                        if (username == null) put("username", "invalid")
                        if (email == null) put("email", "invalid")
                        if (command.firstName.length > 128) put("firstName", "too_long")
                        if (command.lastName.length > 128) put("lastName", "too_long")
                    }
                    if (fields.isNotEmpty()) return@step StepResult.Fail(AuthError.ValidationFailed(fields))

                    when (val verdict = passwordPolicy.evaluate(command.password, username, email)) {
                        PasswordPolicyResult.Acceptable -> Unit
                        is PasswordPolicyResult.Rejected -> return@step StepResult.Fail(
                            AuthError.ValidationFailed(
                                mapOf("password" to verdict.reasons.joinToString(",") { it.token }),
                            ),
                        )
                    }

                    state[usernameKey] = username!!
                    state[emailKey] = email!!
                    StepResult.Continue
                },
            )

            step(
                step("create-account") { command, context, state ->
                    val username = state.require(usernameKey)
                    val email = state.require(emailKey)

                    // A pre-check would still race; the unique indexes are the real guard. The
                    // read only lets us take the identical-response path without a rollback.
                    val taken = users.findByUsername(username) != null || users.findByEmail(email) != null
                    if (taken) {
                        // Same shape, same cost, same response as a real registration.
                        passwordHasher.verifyDummy(command.password)
                        log.info("registration for an existing identifier answered generically")
                        state[duplicateKey] = true
                        return@step StepResult.Continue
                    }

                    val user = User(
                        id = UserId.random(),
                        username = username,
                        primaryEmail = email,
                        firstName = command.firstName.trim(),
                        lastName = command.lastName.trim(),
                        status = UserStatus.PENDING_EMAIL_VERIFICATION,
                        emailVerifiedAt = null,
                        createdAt = context.now,
                        updatedAt = context.now,
                        version = 0,
                    )
                    users.insert(user)
                    credentials.upsert(user.id, passwordHasher.hash(command.password), context.now)
                    roles.assign(user.id, setOf(dev.kamiql.helium.domain.policy.Role.USER))

                    state[userKey] = user
                    state[verificationTokenKey] = verificationTokens.issue(
                        userId = user.id,
                        purpose = VerificationPurpose.EMAIL_VERIFICATION,
                        now = context.now,
                    )
                    StepResult.Continue
                },
            )

            effect(
                effect("registration-events") { _, _, state ->
                    val user = state[userKey] ?: return@effect emptyList()
                    val token = state.require(verificationTokenKey)
                    listOf(
                        DomainEvent.UserRegistered(user.id),
                        DomainEvent.EmailVerificationRequested(
                            userId = user.id,
                            tokenId = token.plaintext,
                            purpose = VerificationPurpose.EMAIL_VERIFICATION,
                        ),
                    )
                },
            )

            result { RegisterAccepted }
        }

    /** Redeems an email verification token and activates the account. */
    val verifyEmail: Flow<VerifyEmailCommand, UserId> =
        flow(FlowId("identity.verify-email")) {
            transaction(TransactionPolicy.Required)
            require(
                RateLimited<VerifyEmailCommand>(
                    "verify-email.ip", RateLimit.EMAIL_VERIFICATION, rateLimiter,
                ) { _, context -> context.ipAddress },
            )

            step(
                step("redeem-token") { command, context, state ->
                    val record = verificationTokens.redeem(
                        command.token, VerificationPurpose.EMAIL_VERIFICATION, context.now,
                    ) ?: return@step StepResult.Fail(AuthError.InvalidToken)

                    users.markEmailVerified(record.userId, context.now)
                    state[userIdKey] = record.userId
                    StepResult.Continue
                },
            )

            effect(
                effect("email-verified") { _, _, state ->
                    listOf(DomainEvent.EmailVerified(state.require(userIdKey)))
                },
            )

            result { state -> state.require(userIdKey) }
        }

    /**
     * Resends a verification mail.
     *
     * Answers identically for a known address, an unknown one and an already-verified one.
     */
    val resendVerification: Flow<ResendVerificationCommand, Unit> =
        flow(FlowId("identity.resend-verification")) {
            transaction(TransactionPolicy.Required)
            require(
                RateLimited<ResendVerificationCommand>(
                    "resend-verification.email", RateLimit.EMAIL_VERIFICATION, rateLimiter,
                ) { command, _ -> Normalization.fold(command.email) },
            )

            step(
                step("issue-token") { command, context, state ->
                    val email = EmailAddress.parse(command.email) ?: return@step StepResult.Continue
                    val user = users.findByEmail(email) ?: return@step StepResult.Continue
                    if (user.isEmailVerified || user.status.isDeleted) return@step StepResult.Continue

                    state[userKey] = user
                    state[verificationTokenKey] = verificationTokens.issue(
                        userId = user.id,
                        purpose = VerificationPurpose.EMAIL_VERIFICATION,
                        now = context.now,
                    )
                    StepResult.Continue
                },
            )

            effect(
                effect("verification-requested") { _, _, state ->
                    val user = state[userKey] ?: return@effect emptyList()
                    val token = state.require(verificationTokenKey)
                    listOf(
                        DomainEvent.EmailVerificationRequested(
                            userId = user.id,
                            tokenId = token.plaintext,
                            purpose = VerificationPurpose.EMAIL_VERIFICATION,
                        ),
                    )
                },
            )

            result { }
        }

    // =========================================================================
    // login
    // =========================================================================

    /**
     * Password login.
     *
     * Order matters and follows concept §2.6: rate limit *before* the expensive Argon2
     * verification, resolve the account by normalized identifier, run a dummy verification when
     * there is no account, check status, then MFA policy. Only then is a session issued.
     */
    val login: Flow<LoginCommand, LoginSucceeded> =
        flow(FlowId("identity.login")) {
            transaction(TransactionPolicy.Required)
            auditAs("auth.login")

            require(
                RateLimited<LoginCommand>("login.ip", RateLimit.LOGIN_PER_IP, rateLimiter) { _, context ->
                    context.ipAddress
                },
            )
            require(
                RateLimited<LoginCommand>(
                    "login.account", RateLimit.LOGIN_PER_ACCOUNT_AND_IP, rateLimiter,
                ) { command, context ->
                    "${Normalization.fold(command.identifier)}|${context.ipAddress.orEmpty()}"
                },
            )

            step(
                step("verify-password") { command, context, state ->
                    val user = users.findByLoginIdentifier(command.identifier)

                    if (user == null || user.status.isDeleted) {
                        // Burn equivalent CPU so absence and a wrong password are timing-alike.
                        passwordHasher.verifyDummy(command.password)
                        return@step StepResult.Fail(AuthError.InvalidCredentials)
                    }

                    val credential = credentials.findByUserId(user.id)
                    if (credential == null) {
                        // Provider- or passkey-only account: there is no password to check.
                        passwordHasher.verifyDummy(command.password)
                        return@step StepResult.Fail(AuthError.InvalidCredentials)
                    }

                    if (!passwordHasher.verify(command.password, credential.hash)) {
                        return@step StepResult.Fail(AuthError.InvalidCredentials)
                    }

                    user.toAccessError()?.let { return@step StepResult.Fail(it) }

                    // Transparent upgrade while the plaintext is legitimately in hand.
                    if (passwordHasher.needsRehash(credential.hash)) {
                        credentials.upsert(user.id, passwordHasher.hash(command.password), context.now)
                    }

                    state[userKey] = user
                    StepResult.Continue
                },
            )

            step(
                step("enforce-mfa-policy") { _, context, state ->
                    val user = state.require(userKey)
                    val enrolled = mfaMethods.enrolledMethods(user.id)
                    val privileged = roles.permissionsOf(user.id).any { it in Permission.STEP_UP_REQUIRED }

                    val mfaRequired = when (mfaPolicy) {
                        MfaPolicy.OPTIONAL -> enrolled.isNotEmpty()
                        MfaPolicy.REQUIRED -> true
                        MfaPolicy.REQUIRED_FOR_PRIVILEGED -> privileged
                    }
                    if (!mfaRequired) return@step StepResult.Continue

                    if (enrolled.isEmpty()) {
                        // Policy demands a factor the user has not set up. Refusing here rather
                        // than waving them through is the whole value of the policy.
                        return@step StepResult.Fail(AuthError.Forbidden("mfa:enrollment-required"))
                    }

                    val transactionId = TransactionId(random.token(24))
                    val methods = enrolled + MfaType.RECOVERY_CODE
                    transactions.put(
                        id = transactionId,
                        kind = MFA_TRANSACTION_KIND,
                        payload = user.id.value.toString(),
                        ttl = lifetimes.mfaTransaction,
                    )
                    StepResult.Challenge(
                        ChallengeDescriptor(
                            code = ChallengeDescriptor.MFA_REQUIRED,
                            transactionId = transactionId,
                            expiresAt = context.now.plus(lifetimes.mfaTransaction),
                            methods = methods.map { it.token }.toSet(),
                        ),
                    )
                },
            )

            step(
                step("issue-session") { _, context, state ->
                    val user = state.require(userKey)
                    state[newDeviceKey] =
                        sessionService.isNewDevice(user.id, context, context.now)
                    state[issuedSessionKey] = sessionService.issue(
                        userId = user.id,
                        clientId = context.clientId,
                        methods = setOf(AuthenticationMethod.PASSWORD),
                        context = context,
                    )
                    StepResult.Continue
                },
            )

            effect(
                effect("login-succeeded") { _, _, state ->
                    val user = state.require(userKey)
                    val issued = state.require(issuedSessionKey)
                    listOf(
                        DomainEvent.LoginSucceeded(
                            userId = user.id,
                            sessionId = issued.session.id,
                            clientId = issued.session.clientId,
                            newDevice = state.require(newDeviceKey),
                        ),
                    )
                },
            )

            result { state ->
                val issued = state.require(issuedSessionKey)
                LoginSucceeded(
                    session = issued,
                    userId = issued.session.userId,
                    newDevice = state.require(newDeviceKey),
                )
            }
        }

    /**
     * Completes an MFA challenge and issues the session the first factor earned.
     *
     * The transaction handle is consumed atomically, so a code cannot be replayed against the
     * same challenge even if the attacker races the legitimate user.
     */
    val completeMfa: Flow<CompleteMfaCommand, LoginSucceeded> =
        flow(FlowId("identity.complete-mfa")) {
            transaction(TransactionPolicy.Required)
            auditAs("auth.mfa-completed")

            require(
                RateLimited<CompleteMfaCommand>("mfa.verify", RateLimit.TOTP_VERIFY, rateLimiter) { command, _ ->
                    command.transactionId.value
                },
            )

            step(
                step("verify-second-factor") { command, context, state ->
                    val payload = transactions.take(command.transactionId, MFA_TRANSACTION_KIND)
                        ?: return@step StepResult.Fail(AuthError.MfaExpired)
                    val userId = UserId.parse(payload) ?: return@step StepResult.Fail(AuthError.MfaExpired)

                    val user = users.findById(userId)
                        ?: return@step StepResult.Fail(AuthError.InvalidCredentials)
                    user.toAccessError()?.let { return@step StepResult.Fail(it) }

                    val method = mfaMethods[command.method]
                        ?: return@step StepResult.Fail(AuthError.MfaInvalid)

                    val verification = method.verify(
                        userId = userId,
                        response = dev.kamiql.helium.domain.mfa.MfaResponse(command.code),
                        now = context.now,
                    )
                    when (verification) {
                        is dev.kamiql.helium.domain.mfa.MfaVerificationResult.Verified -> Unit
                        dev.kamiql.helium.domain.mfa.MfaVerificationResult.Expired ->
                            return@step StepResult.Fail(AuthError.MfaExpired)
                        dev.kamiql.helium.domain.mfa.MfaVerificationResult.Rejected -> {
                            // The transaction was already consumed above, so a wrong code costs
                            // the user a full restart. That is intentional: it caps guesses per
                            // challenge at exactly one.
                            return@step StepResult.Fail(AuthError.MfaInvalid)
                        }
                    }

                    state[userKey] = user
                    state[mfaMethodKey] = command.method
                    StepResult.Continue
                },
            )

            step(
                step("issue-session") { command, context, state ->
                    val user = state.require(userKey)
                    val secondFactor = when (command.method) {
                        MfaType.TOTP -> AuthenticationMethod.TOTP
                        MfaType.RECOVERY_CODE -> AuthenticationMethod.RECOVERY_CODE
                        MfaType.WEBAUTHN -> AuthenticationMethod.PASSKEY
                    }
                    state[newDeviceKey] =
                        sessionService.isNewDevice(user.id, context, context.now)
                    state[issuedSessionKey] = sessionService.issue(
                        userId = user.id,
                        clientId = context.clientId,
                        methods = setOf(AuthenticationMethod.PASSWORD, secondFactor),
                        context = context,
                    )
                    StepResult.Continue
                },
            )

            effect(
                effect("login-succeeded") { _, _, state ->
                    val issued = state.require(issuedSessionKey)
                    listOf(
                        DomainEvent.LoginSucceeded(
                            userId = issued.session.userId,
                            sessionId = issued.session.id,
                            clientId = issued.session.clientId,
                            newDevice = state.require(newDeviceKey),
                        ),
                    )
                },
            )

            result { state ->
                val issued = state.require(issuedSessionKey)
                LoginSucceeded(issued, issued.session.userId, state.require(newDeviceKey))
            }
        }

    // =========================================================================
    // sessions
    // =========================================================================

    val logout: Flow<LogoutCommand, Unit> =
        flow(FlowId("identity.logout")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)

            step(
                step("revoke-session") { command, context, _ ->
                    val actor = context.actor
                    if (actor !is Principal.UserSession || actor.sessionId != command.sessionId) {
                        return@step StepResult.Fail(AuthError.Forbidden())
                    }
                    sessions.revoke(command.sessionId, context.now, SessionRevocationReason.USER_LOGOUT)
                    // Tokens seeded by this session die with it; otherwise "sign out" would
                    // leave a refresh token able to mint new access tokens.
                    refreshTokens.revokeFamiliesForSession(command.sessionId, context.now)
                    StepResult.Continue
                },
            )

            result { }
        }

    /** Revokes one of the caller's own sessions from the device list. */
    val revokeSession: Flow<RevokeSessionCommand, Unit> =
        flow(FlowId("identity.revoke-session")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            requirePermission(Permission.ACCOUNT_SESSION_MANAGE)

            step(
                step("revoke") { command, context, _ ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val session = sessions.findById(command.sessionId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)
                    // Ownership check: without it, any authenticated user could sign out any
                    // other user by guessing a session id.
                    if (session.userId != userId) return@step StepResult.Fail(AuthError.NotFound)

                    sessions.revoke(command.sessionId, context.now, SessionRevocationReason.USER_REVOKED_DEVICE)
                    refreshTokens.revokeFamiliesForSession(command.sessionId, context.now)
                    StepResult.Continue
                },
            )

            effect(
                effect("session-revoked") { command, context, _ ->
                    val userId = context.actor.userIdOrNull
                        ?: return@effect emptyList()
                    listOf(
                        DomainEvent.SessionRevoked(
                            userId = userId,
                            sessionId = command.sessionId,
                            reason = SessionRevocationReason.USER_REVOKED_DEVICE,
                            count = 1,
                        ),
                    )
                },
            )

            result { }
        }

    // =========================================================================
    // password
    // =========================================================================

    /**
     * Requests a password reset.
     *
     * Always succeeds from the caller's point of view. An unknown address, a suspended account
     * and a provider-only account all produce the same `202`, because any difference is an
     * enumeration oracle (concept §2.6).
     */
    val requestPasswordReset: Flow<RequestPasswordResetCommand, Unit> =
        flow(FlowId("identity.password-reset.request")) {
            transaction(TransactionPolicy.Required)
            require(
                RateLimited<RequestPasswordResetCommand>(
                    "password-reset.email", RateLimit.PASSWORD_RESET, rateLimiter,
                ) { command, _ -> Normalization.fold(command.email) },
            )
            require(
                RateLimited<RequestPasswordResetCommand>(
                    "password-reset.ip", RateLimit.PASSWORD_RESET, rateLimiter,
                ) { _, context -> context.ipAddress },
            )

            step(
                step("issue-reset-token") { command, context, state ->
                    val email = EmailAddress.parse(command.email) ?: return@step StepResult.Continue
                    val user = users.findByEmail(email) ?: return@step StepResult.Continue
                    if (user.status.isDeleted) return@step StepResult.Continue

                    state[userKey] = user
                    state[verificationTokenKey] = verificationTokens.issue(
                        userId = user.id,
                        purpose = VerificationPurpose.PASSWORD_RESET,
                        now = context.now,
                    )
                    StepResult.Continue
                },
            )

            effect(
                effect("password-reset-requested") { _, _, state ->
                    val user = state[userKey] ?: return@effect emptyList()
                    listOf(
                        DomainEvent.PasswordResetRequested(
                            userId = user.id,
                            tokenId = state.require(verificationTokenKey).plaintext,
                        ),
                    )
                },
            )

            result { }
        }

    /**
     * Completes a password reset.
     *
     * Concept §2.6 spells out the consequences, all of which commit atomically with the new
     * password: refresh families die, other sessions die, and the account owner is notified.
     * A reset is **not** treated as equivalent to MFA — the new session carries only `pwd`.
     */
    val completePasswordReset: Flow<CompletePasswordResetCommand, UserId> =
        flow(FlowId("identity.password-reset.complete")) {
            transaction(TransactionPolicy.Required)
            idempotency(IdempotencyPolicy.Optional)

            step(
                step("redeem-and-validate") { command, context, state ->
                    val record = verificationTokens.redeem(
                        command.token, VerificationPurpose.PASSWORD_RESET, context.now,
                    ) ?: return@step StepResult.Fail(AuthError.InvalidToken)

                    val user = users.findById(record.userId)
                        ?: return@step StepResult.Fail(AuthError.InvalidToken)

                    when (
                        val verdict =
                            passwordPolicy.evaluate(command.newPassword, user.username, user.primaryEmail)
                    ) {
                        PasswordPolicyResult.Acceptable -> Unit
                        is PasswordPolicyResult.Rejected -> return@step StepResult.Fail(
                            AuthError.ValidationFailed(
                                mapOf("password" to verdict.reasons.joinToString(",") { it.token }),
                            ),
                        )
                    }

                    state[userKey] = user
                    StepResult.Continue
                },
            )

            step(
                step("store-password") { command, context, state ->
                    val user = state.require(userKey)
                    credentials.upsert(user.id, passwordHasher.hash(command.newPassword), context.now)
                    // A user who could not sign in may also never have verified their address;
                    // proving control of the mailbox now is equivalent evidence.
                    if (!user.isEmailVerified) users.markEmailVerified(user.id, context.now)
                    StepResult.Continue
                },
            )

            commitAction(
                commitAction("revoke-everything") { _, context, state ->
                    val user = state.require(userKey)
                    sessions.revokeAllForUser(user.id, context.now, SessionRevocationReason.PASSWORD_RESET)
                    refreshTokens.revokeFamiliesForUser(user.id, context.now)
                },
            )

            effect(
                effect("password-reset-completed") { _, _, state ->
                    listOf(DomainEvent.PasswordResetCompleted(state.require(userKey).id))
                },
            )

            result { state -> state.require(userKey).id }
        }

    /**
     * Changes the password of the signed-in user.
     *
     * This is concept §8.2's worked example, and the requirement list is the reason the flow
     * engine exists at all.
     */
    val changePassword: Flow<ChangePasswordCommand, Unit> =
        flow(FlowId("account.change-password")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            require(EmailVerified(users))
            requirePermission(Permission.ACCOUNT_PASSWORD_CHANGE)

            step(
                step("validate-current-password") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val user = users.findById(userId)
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val credential = credentials.findByUserId(userId)
                        ?: return@step StepResult.Fail(AuthError.InvalidCredentials)

                    if (!passwordHasher.verify(command.currentPassword, credential.hash)) {
                        return@step StepResult.Fail(AuthError.InvalidCredentials)
                    }
                    state[userKey] = user
                    StepResult.Continue
                },
            )

            step(
                step("validate-new-password") { command, _, state ->
                    val user = state.require(userKey)
                    when (
                        val verdict =
                            passwordPolicy.evaluate(command.newPassword, user.username, user.primaryEmail)
                    ) {
                        PasswordPolicyResult.Acceptable -> StepResult.Continue
                        is PasswordPolicyResult.Rejected -> StepResult.Fail(
                            AuthError.ValidationFailed(
                                mapOf("password" to verdict.reasons.joinToString(",") { it.token }),
                            ),
                        )
                    }
                },
            )

            step(
                step("hash-and-store") { command, context, state ->
                    val user = state.require(userKey)
                    credentials.upsert(user.id, passwordHasher.hash(command.newPassword), context.now)
                    StepResult.Continue
                },
            )

            commitAction(
                commitAction("revoke-other-sessions") { _, context, state ->
                    val user = state.require(userKey)
                    val currentSession = (context.actor as? Principal.UserSession)?.sessionId
                    sessions.revokeAllForUser(
                        userId = user.id,
                        at = context.now,
                        reason = SessionRevocationReason.PASSWORD_CHANGED,
                        // Keep the caller signed in; logging people out of the tab they are
                        // using teaches them to ignore security mail.
                        except = currentSession,
                    )
                    refreshTokens.revokeFamiliesForUser(user.id, context.now)
                },
            )

            effect(
                effect("password-changed") { _, _, state ->
                    listOf(DomainEvent.PasswordChanged(state.require(userKey).id))
                },
            )

            result { }
        }

    // =========================================================================
    // email change
    // =========================================================================

    /**
     * Starts an email change. Nothing changes yet — the address stays pending until the new
     * mailbox is proven (concept §2.6: "Commit only after successful verification").
     */
    val requestEmailChange: Flow<RequestEmailChangeCommand, Unit> =
        flow(FlowId("account.email-change.request")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ACCOUNT_EMAIL_CHANGE)

            step(
                step("validate") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val user = users.findById(userId)
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val newEmail = EmailAddress.parse(command.newEmail)
                        ?: return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("email" to "invalid")),
                        )

                    val credential = credentials.findByUserId(userId)
                    if (credential != null && !passwordHasher.verify(command.currentPassword, credential.hash)) {
                        return@step StepResult.Fail(AuthError.InvalidCredentials)
                    }

                    if (newEmail.normalized == user.primaryEmail.normalized) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("email" to "unchanged")),
                        )
                    }

                    state[userKey] = user
                    state[emailKey] = newEmail
                    // The token is only sent to the *new* address, so an attacker who has the
                    // session but not the mailbox cannot complete the change.
                    state[verificationTokenKey] = verificationTokens.issue(
                        userId = user.id,
                        purpose = VerificationPurpose.EMAIL_CHANGE,
                        now = context.now,
                        payload = newEmail.display,
                    )
                    StepResult.Continue
                },
            )

            effect(
                effect("email-change-requested") { _, _, state ->
                    val user = state.require(userKey)
                    listOf(
                        DomainEvent.EmailVerificationRequested(
                            userId = user.id,
                            tokenId = state.require(verificationTokenKey).plaintext,
                            purpose = VerificationPurpose.EMAIL_CHANGE,
                        ),
                    )
                },
            )

            result { }
        }

    /** Confirms an email change with the token delivered to the new address. */
    val confirmEmailChange: Flow<ConfirmEmailChangeCommand, Unit> =
        flow(FlowId("account.email-change.confirm")) {
            transaction(TransactionPolicy.Required)

            step(
                step("apply-change") { command, context, state ->
                    val record = verificationTokens.redeem(
                        command.token, VerificationPurpose.EMAIL_CHANGE, context.now,
                    ) ?: return@step StepResult.Fail(AuthError.InvalidToken)

                    val user = users.findById(record.userId)
                        ?: return@step StepResult.Fail(AuthError.InvalidToken)
                    val newEmail = record.payload?.let(EmailAddress::parse)
                        ?: return@step StepResult.Fail(AuthError.InvalidToken)

                    // Re-check at commit time: the address may have been claimed by somebody
                    // else in the window between request and confirmation.
                    if (users.findByEmail(newEmail)?.takeIf { it.id != user.id } != null) {
                        return@step StepResult.Fail(AuthError.Conflict)
                    }

                    state[previousEmailKey] = user.primaryEmail.normalized
                    users.changePrimaryEmail(user.id, newEmail, context.now)
                    state[userKey] = user
                    StepResult.Continue
                },
            )

            effect(
                effect("email-changed") { _, _, state ->
                    listOf(
                        DomainEvent.EmailChanged(
                            userId = state.require(userKey).id,
                            previousEmailNormalized = state.require(previousEmailKey),
                        ),
                    )
                },
            )

            result { }
        }

    // =========================================================================
    // profile and deletion
    // =========================================================================

    val updateProfile: Flow<UpdateProfileCommand, User> =
        flow(FlowId("account.update-profile")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)

            step(
                step("apply") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    val user = users.findById(userId)
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    val username = command.username?.let { raw ->
                        Username.parse(raw) ?: return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("username" to "invalid")),
                        )
                    }
                    if (username != null && username.normalized != user.username.normalized &&
                        users.findByUsername(username) != null
                    ) {
                        return@step StepResult.Fail(AuthError.Conflict)
                    }

                    val updated = users.update(
                        user.copy(
                            username = username ?: user.username,
                            firstName = command.firstName?.trim() ?: user.firstName,
                            lastName = command.lastName?.trim() ?: user.lastName,
                            updatedAt = context.now,
                        ),
                    )
                    state[userKey] = updated
                    StepResult.Continue
                },
            )

            result { state -> state.require(userKey) }
        }

    /**
     * Soft-deletes the caller's account.
     *
     * Credentials and sessions go immediately; the row and its audit trail are retained per
     * concept §3.4.
     */
    val deleteAccount: Flow<DeleteAccountCommand, Unit> =
        flow(FlowId("account.delete")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))

            step(
                step("verify-and-delete") { command, context, state ->
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

                    credentials.delete(userId)
                    users.softDelete(userId, context.now)
                    state[userIdKey] = userId
                    StepResult.Continue
                },
            )

            commitAction(
                commitAction("revoke-everything") { _, context, state ->
                    val userId = state.require(userIdKey)
                    sessions.revokeAllForUser(userId, context.now, SessionRevocationReason.ACCOUNT_DELETED)
                    refreshTokens.revokeFamiliesForUser(userId, context.now)
                },
            )

            effect(
                effect("account-deleted") { _, _, state ->
                    listOf(DomainEvent.AccountDeleted(state.require(userIdKey)))
                },
            )

            result { }
        }

    // --- shared state keys ------------------------------------------------------

    private val usernameKey = FlowStateKey<Username>("username")
    private val emailKey = FlowStateKey<EmailAddress>("email")
    private val userIdKey = FlowStateKey<UserId>("user_id")
    private val duplicateKey = FlowStateKey<Boolean>("duplicate")
    private val mfaMethodKey = FlowStateKey<MfaType>("mfa_method")

    companion object {
        /** Kind used for MFA handles in the security transaction store. */
        const val MFA_TRANSACTION_KIND: String = "mfa"
    }
}
