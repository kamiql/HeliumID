package dev.kamiql.helium.domain.policy

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.session.AuthenticationMethod

/**
 * A permission is a stable string in `resource:action` form. Strings rather than an enum,
 * because deployments add their own without recompiling this module — but the built-in set
 * below is closed and referenced from code.
 */
@JvmInline
value class Permission(val value: String) {
    override fun toString(): String = value

    companion object {
        // account self-service
        val ACCOUNT_PASSWORD_CHANGE = Permission("account:password:change")
        val ACCOUNT_EMAIL_CHANGE = Permission("account:email:change")
        val ACCOUNT_MFA_MANAGE = Permission("account:mfa:manage")
        val ACCOUNT_PROVIDER_MANAGE = Permission("account:provider:manage")
        val ACCOUNT_SESSION_MANAGE = Permission("account:session:manage")

        // administration
        val ADMIN_USER_READ = Permission("admin:user:read")
        val ADMIN_USER_WRITE = Permission("admin:user:write")
        val ADMIN_USER_DELETE = Permission("admin:user:delete")
        val ADMIN_ROLE_READ = Permission("admin:role:read")
        val ADMIN_ROLE_WRITE = Permission("admin:role:write")
        val ADMIN_CLIENT_READ = Permission("admin:client:read")
        val ADMIN_CLIENT_WRITE = Permission("admin:client:write")
        val ADMIN_AUDIT_READ = Permission("admin:audit:read")

        /**
         * Operations that always demand recent reauthentication and, where enrolled, MFA.
         * Concept §4.10 "Account-takeover protections".
         *
         * This names *operations*, not accounts. Every account can change its own password, so
         * holding one of these says nothing about how privileged the holder is — see
         * [PRIVILEGED_ACCOUNT] for that question, and do not substitute one for the other.
         */
        val STEP_UP_REQUIRED: Set<Permission> = setOf(
            ACCOUNT_PASSWORD_CHANGE,
            ACCOUNT_EMAIL_CHANGE,
            ACCOUNT_MFA_MANAGE,
            ACCOUNT_PROVIDER_MANAGE,
            ADMIN_USER_WRITE,
            ADMIN_USER_DELETE,
            ADMIN_ROLE_WRITE,
            ADMIN_CLIENT_WRITE,
        )

        /**
         * Permissions that make an *account* privileged: it can act on other people's accounts,
         * roles or clients. This is what "privileged" means to the login flow — which MFA policy
         * applies, and whether a trusted device may buy an exemption.
         *
         * Deliberately excludes the `account:*` self-service permissions. Those appear in
         * [STEP_UP_REQUIRED] because changing your own password is a sensitive *operation*, but
         * the built-in `USER` role grants four of them to every account in the system. Reading
         * account privilege out of that set makes every user privileged, and under
         * `MfaPolicy.REQUIRED_FOR_PRIVILEGED` that is a deadlock: a fresh account is refused login
         * until it enrols a factor, and enrolling a factor requires being logged in.
         */
        val PRIVILEGED_ACCOUNT: Set<Permission> = setOf(
            ADMIN_USER_WRITE,
            ADMIN_USER_DELETE,
            ADMIN_ROLE_WRITE,
            ADMIN_CLIENT_WRITE,
        )

        val ALL: List<Permission> = listOf(
            ACCOUNT_PASSWORD_CHANGE, ACCOUNT_EMAIL_CHANGE, ACCOUNT_MFA_MANAGE,
            ACCOUNT_PROVIDER_MANAGE, ACCOUNT_SESSION_MANAGE,
            ADMIN_USER_READ, ADMIN_USER_WRITE, ADMIN_USER_DELETE,
            ADMIN_ROLE_READ, ADMIN_ROLE_WRITE,
            ADMIN_CLIENT_READ, ADMIN_CLIENT_WRITE, ADMIN_AUDIT_READ,
        )
    }
}

/**
 * A named bundle of permissions.
 *
 * Roles do not inherit from each other: a flattened set is far easier to audit than a graph,
 * and "why does this user have that permission" stays a one-hop question.
 */
data class Role(
    val name: String,
    val description: String,
    val color: String,
    val permissions: Set<Permission>,
    /** Built-in roles cannot be deleted or have their name changed. */
    val builtIn: Boolean,
) {
    companion object {
        const val ADMINISTRATOR: String = "ADMINISTRATOR"
        const val USER: String = "USER"

        /** Seeded by migration; the admin UI may edit only non-built-in roles. */
        val BUILT_IN: List<Role> = listOf(
            Role(
                name = ADMINISTRATOR,
                description = "Full administrative access to users, clients and audit data.",
                color = "#EF4444",
                permissions = Permission.ALL.toSet(),
                builtIn = true,
            ),
            Role(
                name = USER,
                description = "Standard account self-service.",
                color = "#5865F2",
                permissions = setOf(
                    Permission.ACCOUNT_PASSWORD_CHANGE,
                    Permission.ACCOUNT_EMAIL_CHANGE,
                    Permission.ACCOUNT_MFA_MANAGE,
                    Permission.ACCOUNT_PROVIDER_MANAGE,
                    Permission.ACCOUNT_SESSION_MANAGE,
                ),
                builtIn = true,
            ),
        )
    }
}

/**
 * Who is acting, resolved once per request by the authentication middleware and then passed
 * explicitly through the flow context.
 *
 * CLAUDE.md forbids a global mutable security context, so there is no thread local and no
 * ambient "current user" anywhere in this system.
 */
sealed interface Principal {

    val permissions: Set<Permission>

    fun has(permission: Permission): Boolean = permission in permissions

    /** A human signed in through a browser session cookie. */
    data class UserSession(
        val userId: UserId,
        val sessionId: SessionId,
        override val permissions: Set<Permission>,
        val roles: Set<String>,
        val authenticationMethods: Set<AuthenticationMethod>,
        val emailVerified: Boolean,
    ) : Principal

    /** A human represented by a bearer access token issued to a client. */
    data class TokenBearer(
        val userId: UserId,
        val clientId: ClientId,
        val scopes: Set<String>,
        override val permissions: Set<Permission>,
        val authenticationMethods: Set<AuthenticationMethod>,
    ) : Principal

    /** A machine acting for itself under `client_credentials`. There is no user behind it. */
    data class ServiceClient(
        val clientId: ClientId,
        val scopes: Set<String>,
        override val permissions: Set<Permission>,
    ) : Principal

    /** No credentials presented. Modelled explicitly so `actor == null` never means "trusted". */
    data object Anonymous : Principal {
        override val permissions: Set<Permission> = emptySet()
    }
}

/** The user id behind the principal, or `null` for anonymous and machine principals. */
val Principal.userIdOrNull: UserId?
    get() = when (this) {
        is Principal.UserSession -> userId
        is Principal.TokenBearer -> userId
        is Principal.ServiceClient -> null
        Principal.Anonymous -> null
    }
