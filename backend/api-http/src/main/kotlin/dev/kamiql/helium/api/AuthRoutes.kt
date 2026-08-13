package dev.kamiql.helium.api

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.identity.BeginMfaChallengeCommand
import dev.kamiql.helium.identity.BeginProviderAuthorizationCommand
import dev.kamiql.helium.identity.CompleteMfaCommand
import dev.kamiql.helium.identity.CompleteProviderCallbackCommand
import dev.kamiql.helium.identity.CompletePasswordResetCommand
import dev.kamiql.helium.identity.CompleteReauthenticationCommand
import dev.kamiql.helium.identity.ReauthenticateCommand
import dev.kamiql.helium.identity.LoginCommand
import dev.kamiql.helium.identity.LogoutCommand
import dev.kamiql.helium.identity.MfaChallengeStarted
import dev.kamiql.helium.identity.ProviderCallbackResult
import dev.kamiql.helium.identity.RegisterCommand
import dev.kamiql.helium.identity.RequestPasswordResetCommand
import dev.kamiql.helium.identity.ResendVerificationCommand
import dev.kamiql.helium.identity.TrustedDeviceDirective
import dev.kamiql.helium.identity.VerifyEmailCommand
import dev.kamiql.helium.spi.ProviderIntent
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import java.time.Duration
import java.time.Instant

/**
 * `/v1/auth` — first-party authentication.
 *
 * Concept §5.2 is explicit that this is **not** a replacement for the OAuth authorization
 * endpoint: it exists for the first-party UI and a BFF, and third-party clients must go
 * through `/oauth2/authorize` instead.
 */
fun Route.authRoutes(dependencies: HeliumApiDependencies) = route("/auth") {

    /**
     * Bootstrap for the SPA: who am I, and here is a CSRF token.
     *
     * Always `200`, even when anonymous — a `401` here would make every page load look like an
     * error in the browser console.
     */
    get("/session") {
        val (actor, _) = call.heliumContext(dependencies)
        val csrf = newCsrfToken(dependencies.random)
        call.setCsrfCookie(dependencies.config, csrf)

        val user = when (actor) {
            is Principal.UserSession -> dependencies.users.findById(actor.userId)
            else -> null
        }
        call.respond(
            SessionBootstrapResponse(
                authenticated = user != null,
                user = user?.toResponse(
                    roles = (actor as Principal.UserSession).roles,
                    permissions = actor.permissions.map { it.value }.toSet(),
                    mfaEnabled = dependencies.mfaRepository.listFactors(user.id).any { it.isActive },
                ),
                csrfToken = csrf,
            ),
        )
    }

    /** Password policy, so the UI can show a live checklist instead of guessing. */
    get("/password-requirements") {
        val requirements = dependencies.passwordPolicy.describe()
        call.respond(
            PasswordRequirementsResponse(
                minLength = requirements.minLength,
                maxLength = requirements.maxLength,
                breachedCheck = requirements.breachedCheck,
                rejectsIdentifier = requirements.rejectsIdentifier,
            ),
        )
    }

    post("/register") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<RegisterRequest>()
        val (_, context) = call.heliumContext(dependencies)

        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.register,
            command = RegisterCommand(
                username = body.username,
                email = body.email,
                password = Secret.of(body.password),
                firstName = body.firstName,
                lastName = body.lastName,
            ),
            context = context,
        )
        // 202 with an opaque body whether or not the account was created (concept §2.6).
        call.respondFlow(result) { call.respond(HttpStatusCode.Accepted, AcceptedResponse()) }
    }

    post("/login") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<LoginRequest>()
        val (_, context) = call.heliumContext(dependencies)

        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.login,
            command = LoginCommand(
                identifier = body.identifier,
                password = Secret.of(body.password),
                // Handed over unexamined. Whether this value earns a skipped challenge is the
                // flow's call; the route cannot even tell a forged cookie from an expired one.
                trustedDeviceToken = call.request.cookies[dependencies.config.trustedDeviceCookieName].asSecret(),
            ),
            context = context,
        )
        call.respondFlow(result) { success ->
            call.issueSession(dependencies, success.session)
            call.applyTrustedDevice(dependencies, success.trustedDevice, context.now)
            call.respond(HttpStatusCode.NoContent)
        }
    }

    /**
     * Hands out the nonce the chosen method needs before it can be answered.
     *
     * Reads the transaction without consuming it: fetching a challenge must not burn one of the
     * user's attempts, or a client that renders the passkey prompt twice locks the account out.
     * Answers for every method, with no options for the ones that have nothing to sign, so the
     * client follows one path regardless of which factor it is about to use.
     */
    post("/mfa/challenge") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<MfaChallengeRequest>()
        val method = parseMfaType(body.method)
        if (method == null) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("method" to "unsupported")))
            return@post
        }
        val (_, context) = call.heliumContext(dependencies)

        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.beginMfaChallenge,
            command = BeginMfaChallengeCommand(
                transactionId = TransactionId(body.transactionId),
                method = method,
            ),
            context = context,
        )
        call.respondFlow(result) { started -> call.respond(started.toResponse()) }
    }

    /** Completes an MFA challenge started by `/login`. */
    post("/mfa/verify") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<MfaVerifyRequest>()
        val method = parseMfaType(body.method)
        if (method == null) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("method" to "unsupported")))
            return@post
        }
        val response = when (val read = body.readResponse(method)) {
            is MfaResponseResult.Valid -> read.response
            is MfaResponseResult.Invalid -> {
                call.respondProblem(AuthError.ValidationFailed(mapOf("response" to read.reason)))
                return@post
            }
        }
        val (_, context) = call.heliumContext(dependencies)

        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.completeMfa,
            command = CompleteMfaCommand(
                transactionId = TransactionId(body.transactionId),
                method = method,
                response = response,
                rememberDevice = body.rememberDevice,
            ),
            context = context,
        )
        call.respondFlow(result) { success ->
            call.issueSession(dependencies, success.session)
            call.applyTrustedDevice(dependencies, success.trustedDevice, context.now)
            call.respond(HttpStatusCode.NoContent)
        }
    }

    /**
     * Step-up for the session the browser already has.
     *
     * Answers `204` when the password alone is enough, and `mfa_required` with a one-time handle
     * when the account has a second factor — the same two-phase shape as `/login`, and for the
     * same reason: the password is not held across the challenge.
     *
     * Sets no cookie. That is the whole point of the endpoint existing: the UI used to satisfy a
     * step-up by replaying `/login`, which issued a fresh session every time somebody confirmed
     * a sensitive action, and buried the real devices in the account's session list.
     */
    post("/reauthenticate") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<ReauthenticateRequest>()
        val (_, context) = call.heliumContext(dependencies)

        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.reauthenticate,
            command = ReauthenticateCommand(Secret.of(body.password)),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    /**
     * Completes a step-up challenge.
     *
     * Separate from `/mfa/verify` because the two spend different handles and buy different
     * things: that one issues a session, this one refreshes an existing one. A single endpoint
     * would have to decide which by inspecting the handle, and the day it guessed wrong a
     * confirmation prompt would mint a session.
     */
    post("/reauthenticate/mfa") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<MfaVerifyRequest>()
        val method = parseMfaType(body.method)
        if (method == null) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("method" to "unsupported")))
            return@post
        }
        val response = when (val read = body.readResponse(method)) {
            is MfaResponseResult.Valid -> read.response
            is MfaResponseResult.Invalid -> {
                call.respondProblem(AuthError.ValidationFailed(mapOf("response" to read.reason)))
                return@post
            }
        }
        val (_, context) = call.heliumContext(dependencies)

        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.completeReauthentication,
            // `remember_device` is read off the wire by the shared DTO and dropped here on
            // purpose: trusting a device lowers the bar for future sign-ins, and a step-up
            // prompt must not be a place to grant that.
            command = CompleteReauthenticationCommand(
                transactionId = TransactionId(body.transactionId),
                method = method,
                response = response,
            ),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    post("/logout") {
        if (!call.enforceCsrf(dependencies)) return@post
        val (actor, context) = call.heliumContext(dependencies)
        val sessionId = (actor as? Principal.UserSession)?.sessionId
        if (sessionId == null) {
            // Already signed out. Clearing the cookie and answering 204 keeps logout idempotent
            // rather than surfacing an error the user cannot act on.
            call.clearSessionCookie(dependencies.config)
            call.respond(HttpStatusCode.NoContent)
            return@post
        }

        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.logout,
            command = LogoutCommand(sessionId),
            context = context,
        )
        call.clearSessionCookie(dependencies.config)
        call.respondFlowNoContent(result)
    }

    post("/email/verify") {
        val body = call.receive<TokenRequestBody>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.verifyEmail,
            command = VerifyEmailCommand(Secret.of(body.token)),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    post("/email/resend") {
        val body = call.receive<EmailRequest>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.resendVerification,
            command = ResendVerificationCommand(body.email),
            context = context,
        )
        call.respondFlow(result) { call.respond(HttpStatusCode.Accepted, AcceptedResponse()) }
    }

    post("/password-reset/request") {
        val body = call.receive<EmailRequest>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.requestPasswordReset,
            command = RequestPasswordResetCommand(body.email),
            context = context,
        )
        // Identical response for known and unknown addresses.
        call.respondFlow(result) { call.respond(HttpStatusCode.Accepted, AcceptedResponse()) }
    }

    post("/password-reset/complete") {
        val body = call.receive<PasswordResetCompleteRequest>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.completePasswordReset,
            command = CompletePasswordResetCommand(
                token = Secret.of(body.token),
                newPassword = Secret.of(body.newPassword),
            ),
            context = context,
        )
        // No session is issued here: a reset proves mailbox control, not identity, and signing
        // the user straight in would make a stolen inbox equivalent to a stolen account.
        call.respondFlowNoContent(result)
    }

    // --- external providers ---------------------------------------------------

    get("/providers") {
        call.respond(ProviderListResponse(dependencies.providers.available.map { it.value }.sorted()))
    }

    /** Starts a provider round trip. `intent=link` requires an authenticated session. */
    get("/providers/{provider}/start") {
        val providerKey = call.parameters["provider"]
            ?.let { runCatching { ProviderKey(it) }.getOrNull() }
        if (providerKey == null) {
            call.respondProblem(AuthError.NotFound)
            return@get
        }
        val intent = if (call.request.queryParameters["intent"] == "link") {
            ProviderIntent.LINK
        } else {
            ProviderIntent.SIGN_IN
        }

        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.providerFlows.beginAuthorization,
            command = BeginProviderAuthorizationCommand(
                provider = providerKey,
                redirectUri = "${dependencies.config.issuerUrl.trimEnd('/')}/v1/auth/providers/${providerKey.value}/callback",
                intent = intent,
            ),
            context = context,
        )
        call.respondFlow(result) { started ->
            // The transaction handle rides in a short-lived, HttpOnly cookie so the browser
            // returns it on the callback without it ever being readable by script.
            call.response.cookies.append(
                name = dependencies.config.providerStateCookieName,
                value = started.transactionId.value,
                maxAge = Duration.ofMinutes(10).seconds,
                path = "/",
                secure = dependencies.config.secureCookies,
                httpOnly = true,
                extensions = mapOf("SameSite" to "Lax"),
            )
            call.respondRedirect(started.authorizationUrl)
        }
    }

    get("/providers/{provider}/callback") {
        val providerKey = call.parameters["provider"]
            ?.let { runCatching { ProviderKey(it) }.getOrNull() }
        val code = call.request.queryParameters["code"]
        val state = call.request.queryParameters["state"]
        val transactionId = call.request.cookies[dependencies.config.providerStateCookieName]

        if (providerKey == null || code == null || state == null || transactionId == null) {
            call.respondProblem(AuthError.OAuthStateInvalid)
            return@get
        }

        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.providerFlows.completeCallback,
            command = CompleteProviderCallbackCommand(
                provider = providerKey,
                code = code,
                state = state,
                redirectUri = "${dependencies.config.issuerUrl.trimEnd('/')}/v1/auth/providers/${providerKey.value}/callback",
                transactionId = TransactionId(transactionId),
            ),
            context = context,
        )

        // The handle is single use in the store as well; clearing the cookie keeps the browser
        // from sending a stale value on the next attempt.
        call.response.cookies.append(
            name = dependencies.config.providerStateCookieName,
            value = "",
            maxAge = 0,
            path = "/",
            secure = dependencies.config.secureCookies,
            httpOnly = true,
        )

        call.respondFlow(result) { callbackResult ->
            when (callbackResult) {
                is ProviderCallbackResult.SignedIn -> {
                    call.issueSession(dependencies, callbackResult.session)
                    call.respondRedirect("/")
                }
                is ProviderCallbackResult.Linked -> call.respondRedirect("/account?linked=${callbackResult.provider.value}")
            }
        }
    }
}

/**
 * Wire token to [MfaType].
 *
 * Derived from [MfaType.token] rather than spelled out, so the same string the server emits in
 * an `mfa_required` problem is the one it accepts back — a hand-written `when` is one rename
 * away from advertising a method the parser rejects.
 *
 * `null` for an unknown value: whether that is a 404 or a validation problem is the caller's
 * decision, not this function's.
 */
internal fun parseMfaType(raw: String): MfaType? {
    val token = raw.lowercase()
    return MfaType.entries.firstOrNull { it.token == token }
}

/**
 * Renders a started challenge.
 *
 * `webauthn` is absent for a method with nothing to sign, rather than an empty object: a client
 * that finds options present knows it must run the authenticator ceremony, and one that does not
 * knows to prompt for a typed value. An empty object would make that a field-by-field guess.
 */
internal fun MfaChallengeStarted.toResponse(): MfaChallengeResponse = MfaChallengeResponse(
    method = method.token,
    webauthn = webauthnOptions?.toResponse(),
)

/** Sets the session cookie and a matching CSRF token after a successful authentication. */
internal fun io.ktor.server.application.ApplicationCall.issueSession(
    dependencies: HeliumApiDependencies,
    issued: dev.kamiql.helium.domain.session.IssuedSession,
) {
    val maxAge = Duration.between(
        issued.session.createdAt,
        minOf(issued.session.idleExpiresAt, issued.session.absoluteExpiresAt),
    ).seconds
    setSessionCookie(dependencies.config, issued.cookieValue(), maxAge)
    // A fresh CSRF token per authentication, so a token captured before sign-in is useless
    // afterwards (session-fixation hygiene for the CSRF pair).
    setCsrfCookie(dependencies.config, newCsrfToken(dependencies.random))
}

/**
 * Carries out the flow's trusted-device decision.
 *
 * Both authentication entry points end here rather than each reading the directive themselves:
 * the two paths differ only in how the user proved themselves, and a second copy of this `when`
 * is a second place for a new directive case to be quietly ignored.
 *
 * @param now the instant the flow itself ran on, not a fresh reading. The max-age is the distance
 *        to an absolute expiry the server already committed to, so measuring it from a later
 *        clock read would hand the browser a cookie that outlives the record behind it.
 */
private fun ApplicationCall.applyTrustedDevice(
    dependencies: HeliumApiDependencies,
    directive: TrustedDeviceDirective,
    now: Instant,
) {
    when (directive) {
        is TrustedDeviceDirective.Issue -> setTrustedDeviceCookie(
            config = dependencies.config,
            value = directive.device.cookieValue(),
            // Floored at zero rather than trusted: a non-positive max-age expresses "already
            // expired" to the browser, which is the correct reading of an expiry in the past.
            maxAgeSeconds = Duration.between(now, directive.expiresAt).seconds.coerceAtLeast(0),
        )
        TrustedDeviceDirective.Clear -> clearTrustedDeviceCookie(dependencies.config)
        TrustedDeviceDirective.Keep -> Unit
    }
}
