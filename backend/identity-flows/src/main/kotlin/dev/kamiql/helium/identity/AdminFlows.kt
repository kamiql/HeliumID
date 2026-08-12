package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.policy.userIdOrNull
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.domain.repository.RoleRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.FlowStateKey
import dev.kamiql.helium.flow.StepResult
import dev.kamiql.helium.flow.TransactionPolicy
import dev.kamiql.helium.flow.commitAction
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.requirement.Authenticated
import dev.kamiql.helium.flow.requirement.ReauthenticatedWithin
import dev.kamiql.helium.flow.step

/**
 * Administrative flows.
 *
 * These act on *other people's* accounts, so on top of the permission check they require a
 * recent reauthentication — an administrator's stolen session is worth more than anyone
 * else's, and the audit row must be able to say the human was present.
 */
class AdminFlows(
    private val users: UserRepository,
    private val roles: RoleRepository,
    private val sessions: SessionRepository,
    private val refreshTokens: RefreshTokenRepository,
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
) {

    private val subjectKey = FlowStateKey<UserId>("subject")
    private val revokedKey = FlowStateKey<Int>("revoked")

    /** Suspends, unlocks or restores an account. */
    val updateUserStatus: Flow<AdminUpdateUserStatusCommand, Unit> =
        flow(FlowId("admin.user.status")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_USER_WRITE)

            step(
                step("apply-status") { command, context, state ->
                    val user = users.findById(command.userId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)

                    // Deleting through this endpoint would skip the credential cleanup and the
                    // tombstoning that the dedicated delete flow performs.
                    if (command.status == UserStatus.DELETED) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("status" to "use_delete_endpoint")),
                        )
                    }
                    // An administrator locking themselves out is a support ticket, not a
                    // security feature.
                    if (user.id == context.actor.userIdOrNull && command.status != UserStatus.ACTIVE) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("status" to "cannot_target_self")),
                        )
                    }

                    users.updateStatus(command.userId, command.status, context.now)
                    state[subjectKey] = command.userId
                    state[FlowStateKey(FlowRunner.SUBJECT_USER_ID)] = command.userId.value.toString()
                    StepResult.Continue
                },
            )

            commitAction(
                commitAction("revoke-on-lockout") { command, context, _ ->
                    // Suspending an account that keeps working until its session expires is not
                    // a suspension.
                    if (command.status != UserStatus.ACTIVE) {
                        sessions.revokeAllForUser(
                            command.userId, context.now, SessionRevocationReason.ADMIN_ACTION,
                        )
                        refreshTokens.revokeFamiliesForUser(command.userId, context.now)
                    }
                },
            )

            effect(
                effect("status-changed") { command, context, _ ->
                    listOf(
                        DomainEvent.AccountStatusChanged(
                            userId = command.userId,
                            newStatus = command.status.name,
                            actorUserId = context.actor.userIdOrNull,
                        ),
                    )
                },
            )

            result { }
        }

    /** Replaces a user's role assignment. */
    val assignRoles: Flow<AdminAssignRolesCommand, Unit> =
        flow(FlowId("admin.user.roles")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_ROLE_WRITE)

            step(
                step("assign") { command, context, state ->
                    users.findById(command.userId) ?: return@step StepResult.Fail(AuthError.NotFound)

                    val known = roles.listRoles().map { it.name }.toSet()
                    val unknown = command.roles - known
                    if (unknown.isNotEmpty()) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("roles" to "unknown")),
                        )
                    }

                    // Guards against the last administrator demoting themselves and leaving the
                    // deployment with nobody who can grant the role back.
                    if (command.userId == context.actor.userIdOrNull &&
                        Role.ADMINISTRATOR !in command.roles
                    ) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("roles" to "cannot_demote_self")),
                        )
                    }

                    roles.assign(command.userId, command.roles)
                    state[subjectKey] = command.userId
                    StepResult.Continue
                },
            )

            result { }
        }

    /** Signs a user out everywhere. Used when an account is believed compromised. */
    val revokeUserSessions: Flow<AdminRevokeUserSessionsCommand, Int> =
        flow(FlowId("admin.user.revoke-sessions")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            requirePermission(Permission.ADMIN_USER_WRITE)

            step(
                step("revoke") { command, context, state ->
                    users.findById(command.userId) ?: return@step StepResult.Fail(AuthError.NotFound)
                    val count = sessions.revokeAllForUser(
                        command.userId, context.now, SessionRevocationReason.ADMIN_ACTION,
                    )
                    refreshTokens.revokeFamiliesForUser(command.userId, context.now)
                    state[revokedKey] = count
                    state[subjectKey] = command.userId
                    StepResult.Continue
                },
            )

            effect(
                effect("sessions-revoked") { command, _, state ->
                    listOf(
                        DomainEvent.SessionRevoked(
                            userId = command.userId,
                            sessionId = null,
                            reason = SessionRevocationReason.ADMIN_ACTION,
                            count = state.require(revokedKey),
                        ),
                    )
                },
            )

            result { state -> state.require(revokedKey) }
        }
}
