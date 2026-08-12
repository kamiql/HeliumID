package dev.kamiql.helium.api

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.identity.BeginTotpEnrollmentCommand
import dev.kamiql.helium.identity.ChangePasswordCommand
import dev.kamiql.helium.identity.ConfirmEmailChangeCommand
import dev.kamiql.helium.identity.ConfirmTotpEnrollmentCommand
import dev.kamiql.helium.identity.DeleteAccountCommand
import dev.kamiql.helium.identity.DisableTotpCommand
import dev.kamiql.helium.identity.RegenerateRecoveryCodesCommand
import dev.kamiql.helium.identity.RequestEmailChangeCommand
import dev.kamiql.helium.identity.RevokeSessionCommand
import dev.kamiql.helium.identity.UnlinkProviderCommand
import dev.kamiql.helium.identity.UpdateProfileCommand
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.route

/**
 * `/v1/me` — account self-service (concept §5.2).
 *
 * Authorization lives in the flows, not here. These handlers parse, delegate and map; if you
 * find a security decision creeping into one of them, it belongs in a requirement instead
 * (CLAUDE.md §1.4).
 */
fun Route.accountRoutes(dependencies: HeliumApiDependencies) = route("/me") {

    get {
        val (actor, _) = call.heliumContext(dependencies)
        val session = actor as? Principal.UserSession
        val userId = when (actor) {
            is Principal.UserSession -> actor.userId
            is Principal.TokenBearer -> actor.userId
            else -> {
                call.respondProblem(AuthError.AuthenticationRequired)
                return@get
            }
        }
        val user = dependencies.users.findById(userId)
        if (user == null) {
            call.respondProblem(AuthError.AuthenticationRequired)
            return@get
        }
        call.respond(
            user.toResponse(
                roles = session?.roles ?: dependencies.roles.rolesOf(userId),
                permissions = actor.permissions.map { it.value }.toSet(),
                mfaEnabled = dependencies.mfaRepository.listFactors(userId).any { it.isActive },
            ),
        )
    }

    put {
        if (!call.enforceCsrf(dependencies)) return@put
        val body = call.receive<UpdateProfileRequest>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.updateProfile,
            command = UpdateProfileCommand(body.username, body.firstName, body.lastName),
            context = context,
        )
        call.respondFlow(result) { user ->
            call.respond(
                user.toResponse(
                    roles = dependencies.roles.rolesOf(user.id),
                    permissions = dependencies.roles.permissionsOf(user.id).map { it.value }.toSet(),
                    mfaEnabled = dependencies.mfaRepository.listFactors(user.id).any { it.isActive },
                ),
            )
        }
    }

    put("/password") {
        if (!call.enforceCsrf(dependencies)) return@put
        val body = call.receive<ChangePasswordRequest>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.changePassword,
            command = ChangePasswordCommand(
                currentPassword = Secret.of(body.currentPassword),
                newPassword = Secret.of(body.newPassword),
            ),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    post("/email-change") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<EmailChangeRequest>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.requestEmailChange,
            command = RequestEmailChangeCommand(body.newEmail, Secret.of(body.currentPassword)),
            context = context,
        )
        call.respondFlow(result) { call.respond(HttpStatusCode.Accepted, AcceptedResponse()) }
    }

    /** Confirms with the token sent to the *new* address; needs no session of its own. */
    post("/email-change/confirm") {
        val body = call.receive<TokenRequestBody>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.confirmEmailChange,
            command = ConfirmEmailChangeCommand(Secret.of(body.token)),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    post("/delete") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<DeleteAccountRequest>()
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.deleteAccount,
            command = DeleteAccountCommand(body.currentPassword?.let(Secret::of)),
            context = context,
        )
        if (result is dev.kamiql.helium.flow.FlowResult.Success) {
            call.clearSessionCookie(dependencies.config)
        }
        call.respondFlowNoContent(result)
    }

    // --- sessions ----------------------------------------------------------

    get("/sessions") {
        val (actor, context) = call.heliumContext(dependencies)
        val userId = when (actor) {
            is Principal.UserSession -> actor.userId
            is Principal.TokenBearer -> actor.userId
            else -> {
                call.respondProblem(AuthError.AuthenticationRequired)
                return@get
            }
        }
        val current = (actor as? Principal.UserSession)?.sessionId
        val sessions = dependencies.sessions.listActiveForUser(userId, context.now)
        call.respond(sessions.map { it.toResponse(current = it.id == current) })
    }

    delete("/sessions/{sessionId}") {
        if (!call.enforceCsrf(dependencies)) return@delete
        val sessionId = call.parameters["sessionId"]?.let(SessionId::parse)
        if (sessionId == null) {
            call.respondProblem(AuthError.NotFound)
            return@delete
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.identityFlows.revokeSession,
            command = RevokeSessionCommand(sessionId),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    // --- MFA ----------------------------------------------------------------

    get("/mfa") {
        val (actor, _) = call.heliumContext(dependencies)
        val userId = when (actor) {
            is Principal.UserSession -> actor.userId
            is Principal.TokenBearer -> actor.userId
            else -> {
                call.respondProblem(AuthError.AuthenticationRequired)
                return@get
            }
        }
        call.respond(dependencies.mfaRepository.listFactors(userId).map { it.toResponse() })
    }

    post("/mfa/totp/enroll") {
        if (!call.enforceCsrf(dependencies)) return@post
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.mfaFlows.beginTotpEnrollment,
            command = BeginTotpEnrollmentCommand,
            context = context,
        )
        call.respondFlow(result) { started ->
            call.respond(
                TotpEnrollmentResponse(
                    factorId = started.factorId.value.toString(),
                    secret = started.secret,
                    otpauthUri = started.otpauthUri,
                ),
            )
        }
    }

    post("/mfa/totp/confirm") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<TotpConfirmRequest>()
        val factorId = MfaFactorId.parse(body.factorId)
        if (factorId == null) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("factor_id" to "invalid")))
            return@post
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.mfaFlows.confirmTotpEnrollment,
            command = ConfirmTotpEnrollmentCommand(factorId, Secret.of(body.code)),
            context = context,
        )
        // The only response that ever carries recovery codes.
        call.respondFlow(result) { confirmed ->
            call.respond(RecoveryCodesResponse(confirmed.recoveryCodes))
        }
    }

    post("/mfa/totp/disable") {
        if (!call.enforceCsrf(dependencies)) return@post
        val body = call.receive<TotpDisableRequest>()
        val factorId = MfaFactorId.parse(body.factorId)
        if (factorId == null) {
            call.respondProblem(AuthError.ValidationFailed(mapOf("factor_id" to "invalid")))
            return@post
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.mfaFlows.disableTotp,
            command = DisableTotpCommand(factorId, body.currentPassword?.let(Secret::of)),
            context = context,
        )
        call.respondFlowNoContent(result)
    }

    post("/mfa/recovery-codes") {
        if (!call.enforceCsrf(dependencies)) return@post
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.mfaFlows.regenerateRecoveryCodes,
            command = RegenerateRecoveryCodesCommand,
            context = context,
        )
        call.respondFlow(result) { generated -> call.respond(RecoveryCodesResponse(generated.codes)) }
    }

    // --- linked providers -----------------------------------------------------

    get("/providers") {
        val (actor, _) = call.heliumContext(dependencies)
        val userId = when (actor) {
            is Principal.UserSession -> actor.userId
            is Principal.TokenBearer -> actor.userId
            else -> {
                call.respondProblem(AuthError.AuthenticationRequired)
                return@get
            }
        }
        call.respond(dependencies.identities.findByUserId(userId).map { it.toResponse() })
    }

    delete("/providers/{provider}") {
        if (!call.enforceCsrf(dependencies)) return@delete
        val provider = call.parameters["provider"]?.let { runCatching { ProviderKey(it) }.getOrNull() }
        if (provider == null) {
            call.respondProblem(AuthError.NotFound)
            return@delete
        }
        val (_, context) = call.heliumContext(dependencies)
        val result = dependencies.flowRunner.execute(
            flow = dependencies.providerFlows.unlinkProvider,
            command = UnlinkProviderCommand(provider),
            context = context,
        )
        call.respondFlowNoContent(result)
    }
}
