package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.Normalization
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
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
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions
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
import dev.kamiql.helium.domain.session.IssuedTrustedDevice
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.domain.session.TrustedDeviceCheck
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.flow.ChallengeDescriptor
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowState
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
import dev.kamiql.helium.spi.VerificationChallenge
import org.slf4j.LoggerFactory
import java.time.Instant

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
    private val trustedDevices: TrustedDeviceService,
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
    private val trustedDeviceKey =
        FlowStateKey<IssuedTrustedDevice>("trusted_device", sensitive = true)

    /** A device cookie was presented and did not earn trust, so the browser is holding a dud. */
    private val staleTrustedDeviceKey = FlowStateKey<Boolean>("trusted_device_stale")
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
                step("enforce-mfa-policy") { command, context, state ->
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

                    // A device the user previously proved a factor on may skip the challenge.
                    //
                    // This applies under every policy, including REQUIRED, because REQUIRED means
                    // "must have enrolled a factor" — the branch above rejects an account that has
                    // not — and not "must present it on every sign-in". A deployment that means
                    // the stricter thing sets HELIUM_TRUSTED_DEVICE_DAYS=0.
                    //
                    // Privileged accounts never skip, and the check is bypassed entirely for them
                    // rather than evaluated and discarded: an admin's cookie must not even be
                    // rotated by this path, so that nothing about their login depends on a value
                    // an attacker with the laptop could have copied.
                    if (!privileged) {
                        when (val check = trustedDevices.check(user.id, command.trustedDeviceToken, context, context.now)) {
                            is TrustedDeviceCheck.Trusted -> {
                                state[trustedDeviceKey] = check.rotated
                                return@step StepResult.Continue
                            }

                            // The cookie was copied. The service has already revoked the device
                            // and notified the owner in its own transaction; this login simply
                            // falls through to a full challenge like any other.
                            is TrustedDeviceCheck.Reused,
                            TrustedDeviceCheck.NotTrusted,
                            -> state[staleTrustedDeviceKey] = true
                        }
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
                    buildList {
                        add(
                            DomainEvent.LoginSucceeded(
                                userId = user.id,
                                sessionId = issued.session.id,
                                clientId = issued.session.clientId,
                                newDevice = state.require(newDeviceKey),
                            ),
                        )
                        // Records that this sign-in skipped the second factor. Without it the
                        // audit trail cannot distinguish a full login from a trusted-device one.
                        state[trustedDeviceKey]?.let {
                            add(DomainEvent.TrustedDeviceUsed(user.id, it.device.id))
                        }
                    }
                },
            )

            result { state ->
                val issued = state.require(issuedSessionKey)
                LoginSucceeded(
                    session = issued,
                    userId = issued.session.userId,
                    newDevice = state.require(newDeviceKey),
                    trustedDevice = when {
                        state[trustedDeviceKey] != null -> state.require(trustedDeviceKey)
                            .let { TrustedDeviceDirective.Issue(it, it.device.expiresAt) }

                        // The browser sent a cookie that bought it nothing — expired, revoked,
                        // or replayed. Reaching this line means the login succeeded anyway
                        // (no factor was required), so take the opportunity to bin the value
                        // rather than let it be re-presented on every future sign-in.
                        state[staleTrustedDeviceKey] == true -> TrustedDeviceDirective.Clear

                        else -> TrustedDeviceDirective.Keep
                    },
                )
            }
        }

    /**
     * Hands out the server-chosen nonce a signing method needs before it can be answered.
     *
     * Runs between the password and the second factor, so there is no session yet and the flow
     * declares no authentication requirement — exactly like [completeMfa]. The MFA transaction
     * is the only thing authorizing the call, and it is **peeked, never taken**: consuming it
     * here would mean asking for a challenge burned the user's one attempt, turning every
     * passkey sign-in into a guaranteed restart.
     *
     * A method with nothing to hand out — TOTP, recovery codes — is a success with no options,
     * not an error. The caller asked what it needs to answer, and the honest answer is
     * "nothing".
     */
    val beginMfaChallenge: Flow<BeginMfaChallengeCommand, MfaChallengeStarted> =
        flow(FlowId("identity.begin-mfa-challenge")) {
            transaction(TransactionPolicy.Required)
            auditAs("auth.mfa-challenge-started")

            // A challenge endpoint with no limit is a free oracle: it accepts an unauthenticated
            // handle and does work for whoever presents one. Two dimensions, because the
            // per-transaction bucket alone is trivially sidestepped by inventing a new
            // transaction id for every request.
            require(
                RateLimited<BeginMfaChallengeCommand>(
                    "mfa.challenge", RateLimit.TOTP_VERIFY, rateLimiter,
                ) { command, _ -> command.transactionId.value },
            )
            require(
                RateLimited<BeginMfaChallengeCommand>(
                    "mfa.challenge.ip", RateLimit.LOGIN_PER_IP, rateLimiter,
                ) { _, context -> context.ipAddress },
            )

            step(
                step("issue-challenge") { command, context, state ->
                    // peek, not take. See the flow comment: this is the single most important
                    // line in it.
                    //
                    // Either kind of handle is accepted: a sign-in challenge and a step-up
                    // challenge need the same nonce for the same account, and this endpoint
                    // hands out nothing that is worth anything without the answer that follows.
                    // Which one it was still decides what completing it buys, and that is
                    // enforced where the handle is spent — never here.
                    val payload = transactions.peek(command.transactionId, MFA_TRANSACTION_KIND)
                        ?: transactions.peek(command.transactionId, REAUTH_TRANSACTION_KIND)
                        ?: return@step StepResult.Fail(AuthError.MfaExpired)
                    val userId = userIdOf(payload)
                        ?: return@step StepResult.Fail(AuthError.MfaExpired)

                    // Absent and suspended accounts answer the same way an expired handle does.
                    // The caller learns only that this handle buys them nothing.
                    val user = users.findById(userId)
                        ?: return@step StepResult.Fail(AuthError.MfaExpired)
                    user.toAccessError()?.let { return@step StepResult.Fail(it) }

                    val method = mfaMethods[command.method]
                        ?: return@step StepResult.Fail(AuthError.MfaInvalid)

                    when (val challenge = method.beginVerification(userId, context.now)) {
                        null -> Unit
                        is VerificationChallenge.WebAuthn -> state[webauthnOptionsKey] = challenge.options
                    }
                    state[mfaMethodKey] = command.method
                    StepResult.Continue
                },
            )

            result { state ->
                MfaChallengeStarted(
                    method = state.require(mfaMethodKey),
                    webauthnOptions = state[webauthnOptionsKey],
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

                    // Passed straight through: the flow does not know, and must not care,
                    // whether this is a typed code or a signed assertion. Deciding which shapes
                    // it accepts is the method's job, and the sealed type makes a mismatch a
                    // rejection rather than a parse error.
                    val verification = method.verify(
                        userId = userId,
                        response = command.response,
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
                    val secondFactor = amrOf(command.method)
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

            step(
                step("remember-device") { command, context, state ->
                    // The one place a trusted device may be minted: a second factor was just
                    // verified. Minting anywhere else — on a password-only login in particular —
                    // would make the first sign-in on a new machine its own bypass.
                    if (!command.rememberDevice) return@step StepResult.Continue

                    val user = state.require(userKey)
                    val privileged = roles.permissionsOf(user.id).any { it in Permission.STEP_UP_REQUIRED }
                    if (privileged) {
                        // Silently ignored rather than rejected: the account still signs in, it
                        // just does not get the exemption. Failing here would turn a checkbox
                        // into a login error for exactly the accounts that must keep working.
                        log.info("ignoring remember-device for privileged user {}", user.id)
                        return@step StepResult.Continue
                    }

                    trustedDevices.remember(user.id, context, context.now)
                        ?.let { state[trustedDeviceKey] = it }
                    StepResult.Continue
                },
            )

            effect(
                effect("login-succeeded") { _, _, state ->
                    val issued = state.require(issuedSessionKey)
                    buildList {
                        add(
                            DomainEvent.LoginSucceeded(
                                userId = issued.session.userId,
                                sessionId = issued.session.id,
                                clientId = issued.session.clientId,
                                newDevice = state.require(newDeviceKey),
                            ),
                        )
                        state[trustedDeviceKey]?.let {
                            add(
                                DomainEvent.TrustedDeviceAdded(
                                    userId = issued.session.userId,
                                    deviceId = it.device.id,
                                    expiresAt = it.device.expiresAt,
                                ),
                            )
                        }
                    }
                },
            )

            result { state ->
                val issued = state.require(issuedSessionKey)
                LoginSucceeded(
                    session = issued,
                    userId = issued.session.userId,
                    newDevice = state.require(newDeviceKey),
                    trustedDevice = state[trustedDeviceKey]
                        ?.let { TrustedDeviceDirective.Issue(it, it.device.expiresAt) }
                    // Getting here at all means a challenge was raised, which means whatever
                    // device cookie this browser holds did not satisfy it. Clearing is therefore
                    // always right when the user did not ask to be remembered again — and it is
                    // the path that finally disposes of a cookie whose device was revoked for
                    // reuse, since that login ended in a challenge and could not say so.
                        ?: TrustedDeviceDirective.Clear,
                )
            }
        }

    // =========================================================================
    // reauthentication (step-up)
    // =========================================================================

    /**
     * Re-proves identity for the session the caller already has.
     *
     * ### Why this is not `login` a second time
     *
     * Freshness is measured from `Session.authenticatedAt`, and for a long time the only thing
     * that moved it was signing in. That made the step-up prompt an alias for `POST /auth/login`,
     * which mints a session — so confirming a deletion, then a password change, then an MFA
     * change left three extra sessions behind, from one browser, in a list whose entire purpose
     * is to let somebody spot the device that should not be there. A device list nobody can read
     * is a security control that has been switched off. This flow moves the clock on the session
     * the browser already holds and issues nothing.
     *
     * ### The bar
     *
     * A second factor is demanded whenever the account has one enrolled, with no trusted-device
     * exemption. That exemption exists so a recognised machine can skip the challenge *at
     * sign-in*; extending it to step-up would mean the operations guarded by step-up — changing
     * the password, removing a factor, deleting the account — are reachable on a stolen session
     * plus a password, from precisely the machine an attacker with both is most likely to be
     * using. It is also the strictly safer direction of the two: every case this covers either
     * matches what replaying login asked for, or asks for more.
     */
    val reauthenticate: Flow<ReauthenticateCommand, Unit> =
        flow(FlowId("identity.reauthenticate")) {
            transaction(TransactionPolicy.Required)
            auditAs("auth.reauthenticated")

            // Anonymous callers get `auth_required`, not a password prompt: there is no session
            // to refresh, and accepting one here would make this a login endpoint after all.
            require(Authenticated)
            require(
                RateLimited<ReauthenticateCommand>("reauth.ip", RateLimit.LOGIN_PER_IP, rateLimiter) { _, context ->
                    context.ipAddress
                },
            )
            // Keyed on the session rather than the account, because that is what the attempts are
            // being spent against. Somebody holding a stolen cookie gets their own small budget
            // and cannot exhaust the owner's by guessing from a second browser.
            require(
                RateLimited<ReauthenticateCommand>(
                    "reauth.session", RateLimit.LOGIN_PER_ACCOUNT_AND_IP, rateLimiter,
                ) { _, context ->
                    (context.actor as? Principal.UserSession)?.sessionId?.value?.toString()
                },
            )

            step(
                step("verify-password") { command, context, state ->
                    val actor = context.actor as? Principal.UserSession
                        // A bearer token has no interactive session to refresh, which is the same
                        // answer `ReauthenticatedWithin` gives such a caller.
                        ?: return@step StepResult.Fail(AuthError.ReauthenticationRequired)

                    val user = users.findById(actor.userId)
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    user.toAccessError()?.let { return@step StepResult.Fail(it) }

                    val credential = credentials.findByUserId(user.id)
                    if (credential == null) {
                        // Provider- or passkey-only account: there is no password to re-present.
                        // Nothing is being enumerated here — the caller already knows whose
                        // account this is — but the dummy keeps the timing of "wrong password"
                        // and "no password" alike, so the shape of the account stays private.
                        passwordHasher.verifyDummy(command.password)
                        return@step StepResult.Fail(AuthError.InvalidCredentials)
                    }
                    if (!passwordHasher.verify(command.password, credential.hash)) {
                        return@step StepResult.Fail(AuthError.InvalidCredentials)
                    }

                    state[userKey] = user
                    state[sessionIdKey] = actor.sessionId
                    StepResult.Continue
                },
            )

            step(
                step("enforce-second-factor") { _, context, state ->
                    val user = state.require(userKey)
                    val enrolled = mfaMethods.enrolledMethods(user.id)
                    if (enrolled.isEmpty()) return@step StepResult.Continue

                    val transactionId = TransactionId(random.token(24))
                    transactions.put(
                        id = transactionId,
                        kind = REAUTH_TRANSACTION_KIND,
                        payload = reauthPayload(user.id, state.require(sessionIdKey)),
                        ttl = lifetimes.mfaTransaction,
                    )
                    StepResult.Challenge(
                        ChallengeDescriptor(
                            code = ChallengeDescriptor.MFA_REQUIRED,
                            transactionId = transactionId,
                            expiresAt = context.now.plus(lifetimes.mfaTransaction),
                            methods = (enrolled + MfaType.RECOVERY_CODE).map { it.token }.toSet(),
                        ),
                    )
                },
            )

            step(
                step("refresh-session") { _, context, state ->
                    refreshStepUpClock(state, context.now, setOf(AuthenticationMethod.PASSWORD))
                },
            )

            effect(
                effect("reauthenticated") { _, _, state ->
                    listOf(
                        DomainEvent.Reauthenticated(
                            userId = state.require(userKey).id,
                            sessionId = state.require(sessionIdKey),
                            mfa = false,
                        ),
                    )
                },
            )

            result { }
        }

    /**
     * Answers the second factor a [reauthenticate] challenge asked for.
     *
     * Mirrors [completeMfa] except in what it produces: no session is issued, no trusted device
     * is minted, and the handle is bound to one session rather than to an account.
     */
    val completeReauthentication: Flow<CompleteReauthenticationCommand, Unit> =
        flow(FlowId("identity.reauthenticate.mfa")) {
            transaction(TransactionPolicy.Required)
            auditAs("auth.reauthenticated")

            require(Authenticated)
            require(
                RateLimited<CompleteReauthenticationCommand>(
                    "reauth.mfa", RateLimit.TOTP_VERIFY, rateLimiter,
                ) { command, _ -> command.transactionId.value },
            )

            step(
                step("verify-second-factor") { command, context, state ->
                    val actor = context.actor as? Principal.UserSession
                        ?: return@step StepResult.Fail(AuthError.ReauthenticationRequired)

                    val payload = transactions.take(command.transactionId, REAUTH_TRANSACTION_KIND)
                        ?: return@step StepResult.Fail(AuthError.MfaExpired)
                    val handle = parseReauthPayload(payload)
                        ?: return@step StepResult.Fail(AuthError.MfaExpired)

                    // The handle is bound to the browser that asked for it, and both halves are
                    // checked. Without the session half, a step-up begun in one session would
                    // refresh the clock of another the same account happens to have open — which
                    // is exactly the pair of sessions that exists during a takeover.
                    if (handle.userId != actor.userId || handle.sessionId != actor.sessionId) {
                        return@step StepResult.Fail(AuthError.MfaExpired)
                    }

                    val user = users.findById(handle.userId)
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    user.toAccessError()?.let { return@step StepResult.Fail(it) }

                    val method = mfaMethods[command.method]
                        ?: return@step StepResult.Fail(AuthError.MfaInvalid)

                    when (method.verify(handle.userId, command.response, context.now)) {
                        is MfaVerificationResult.Verified -> Unit
                        MfaVerificationResult.Expired -> return@step StepResult.Fail(AuthError.MfaExpired)
                        // The handle was consumed above, so a wrong answer costs a restart from
                        // the password — one guess per challenge, as at sign-in.
                        MfaVerificationResult.Rejected -> return@step StepResult.Fail(AuthError.MfaInvalid)
                    }

                    state[userKey] = user
                    state[sessionIdKey] = handle.sessionId
                    state[mfaMethodKey] = command.method
                    StepResult.Continue
                },
            )

            step(
                step("refresh-session") { _, context, state ->
                    refreshStepUpClock(
                        state = state,
                        now = context.now,
                        methods = setOf(
                            AuthenticationMethod.PASSWORD,
                            amrOf(state.require(mfaMethodKey)),
                        ),
                    )
                },
            )

            effect(
                effect("reauthenticated") { _, _, state ->
                    listOf(
                        DomainEvent.Reauthenticated(
                            userId = state.require(userKey).id,
                            sessionId = state.require(sessionIdKey),
                            mfa = true,
                        ),
                    )
                },
            )

            result { }
        }

    /**
     * Moves `authenticatedAt` on the session the step-up was run for.
     *
     * A `false` from the repository means the session was revoked while the user was answering
     * the prompt — from another device, or by an administrator. Reporting that as
     * `AuthenticationRequired` rather than resurrecting the row is the point: a revocation that a
     * step-up could undo is not a revocation.
     */
    private suspend fun refreshStepUpClock(
        state: FlowState,
        now: Instant,
        methods: Set<AuthenticationMethod>,
    ): StepResult {
        val refreshed = sessions.markAuthenticated(state.require(sessionIdKey), now, methods)
        return if (refreshed) StepResult.Continue else StepResult.Fail(AuthError.AuthenticationRequired)
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

    /**
     * Revokes one of the caller's own trusted devices.
     *
     * A flow rather than a direct service call, for the same reason [revokeSession] is one: this
     * changes a security posture and therefore owes the audit log a row. The `false` return from
     * the repository covers "no such device", "someone else's device" and "already revoked"
     * alike, and all three surface as [AuthError.NotFound] — distinguishing them would make the
     * endpoint an oracle for which device ids exist.
     */
    val revokeTrustedDevice: Flow<RevokeTrustedDeviceCommand, Unit> =
        flow(FlowId("identity.revoke-trusted-device")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            requirePermission(Permission.ACCOUNT_SESSION_MANAGE)
            auditAs("auth.trusted-device-revoked")

            step(
                step("revoke") { command, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)

                    val revoked = trustedDevices.revoke(
                        userId = userId,
                        id = command.deviceId,
                        now = context.now,
                        reason = TrustedDeviceRevocationReason.USER_REVOKED,
                    )
                    if (!revoked) return@step StepResult.Fail(AuthError.NotFound)

                    state[userIdKey] = userId
                    StepResult.Continue
                },
            )

            effect(
                effect("trusted-device-revoked") { command, _, state ->
                    listOf(
                        DomainEvent.TrustedDeviceRevoked(
                            userId = state.require(userIdKey),
                            deviceId = command.deviceId,
                            reason = TrustedDeviceRevocationReason.USER_REVOKED,
                            count = 1,
                        ),
                    )
                },
            )

            result { }
        }

    /** Revokes every trusted device the caller has, including the one they are calling from. */
    val revokeAllTrustedDevices: Flow<RevokeAllTrustedDevicesCommand, TrustedDevicesRevoked> =
        flow(FlowId("identity.revoke-trusted-devices")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            requirePermission(Permission.ACCOUNT_SESSION_MANAGE)
            auditAs("auth.trusted-device-revoked")

            step(
                step("revoke-all") { _, context, state ->
                    val userId = context.actor.userIdOrNull
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    state[userIdKey] = userId
                    state[revokedCountKey] = trustedDevices.revokeAll(
                        userId, context.now, TrustedDeviceRevocationReason.USER_REVOKED,
                    )
                    StepResult.Continue
                },
            )

            effect(
                effect("trusted-devices-revoked") { _, _, state ->
                    listOf(
                        DomainEvent.TrustedDeviceRevoked(
                            userId = state.require(userIdKey),
                            // No single id: this is the "forget everything" action.
                            deviceId = null,
                            reason = TrustedDeviceRevocationReason.USER_REVOKED,
                            count = state.require(revokedCountKey),
                        ),
                    )
                },
            )

            result { state -> TrustedDevicesRevoked(state.require(revokedCountKey)) }
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
                    // A reset is the flow someone runs after losing control of the account, so
                    // the MFA exemptions granted before it are exactly what must not survive.
                    trustedDevices.revokeAll(
                        user.id, context.now, TrustedDeviceRevocationReason.PASSWORD_RESET,
                    )
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
                    // No `except` counterpart here: a device exemption is not the session the
                    // user is looking at, so keeping one would silently preserve the weaker
                    // credential while revoking the stronger ones. The next sign-in on this
                    // machine asks for the factor once and the user can tick the box again.
                    trustedDevices.revokeAll(
                        user.id, context.now, TrustedDeviceRevocationReason.PASSWORD_CHANGED,
                    )
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
                    // Explicit, not left to the foreign key: this is a soft delete, so the users
                    // row survives and `ON DELETE CASCADE` never fires.
                    trustedDevices.revokeAll(
                        userId, context.now, TrustedDeviceRevocationReason.ACCOUNT_DELETED,
                    )
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

    /** The session a step-up is refreshing. Not sensitive: an id, not a credential. */
    private val sessionIdKey = FlowStateKey<SessionId>("step_up_session")

    /** Sensitive: the options carry the single-use nonce the authenticator will sign. */
    private val webauthnOptionsKey =
        FlowStateKey<WebAuthnAuthenticationOptions>("webauthn_options", sensitive = true)

    companion object {
        /** Kind used for MFA handles in the security transaction store. */
        const val MFA_TRANSACTION_KIND: String = "mfa"

        /**
         * Kind used for step-up handles.
         *
         * A separate kind, not a flag on the payload. The store looks handles up *by* kind, so
         * this is what makes a step-up handle unspendable at `/auth/mfa/verify`: presenting one
         * there would otherwise mint a whole session out of a prompt the user answered to
         * confirm a deletion.
         */
        const val REAUTH_TRANSACTION_KIND: String = "reauth"

        /** `amr` value for a verified second factor. */
        private fun amrOf(method: MfaType): AuthenticationMethod = when (method) {
            MfaType.TOTP -> AuthenticationMethod.TOTP
            MfaType.RECOVERY_CODE -> AuthenticationMethod.RECOVERY_CODE
            MfaType.WEBAUTHN -> AuthenticationMethod.PASSKEY
        }

        /** Who the step-up is for, and which of their sessions. @see parseReauthPayload */
        private data class ReauthHandle(val userId: UserId, val sessionId: SessionId)

        private fun reauthPayload(userId: UserId, sessionId: SessionId): String =
            "${userId.value}|${sessionId.value}"

        private fun parseReauthPayload(payload: String): ReauthHandle? {
            val userId = UserId.parse(payload.substringBefore('|')) ?: return null
            val sessionId = SessionId.parse(payload.substringAfter('|', "")) ?: return null
            return ReauthHandle(userId, sessionId)
        }

        /**
         * The account a transaction handle belongs to, whichever kind it is.
         *
         * A sign-in handle is a bare user id and a step-up handle carries a session too; both
         * start with the user id, which is all [beginMfaChallenge] needs to know.
         */
        private fun userIdOf(payload: String): UserId? = UserId.parse(payload.substringBefore('|'))
    }
}
