package dev.kamiql.helium.domain.user

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.error.AuthError
import java.time.Instant

/**
 * Account lifecycle states from concept §3.2.
 *
 * The set is closed on purpose: [toAccessError] is the one place that decides whether a state
 * blocks authentication, so a new state cannot be added without deciding that question.
 */
enum class UserStatus {
    /** Created, credentials stored, but the email address is not proven yet. */
    PENDING_EMAIL_VERIFICATION,

    ACTIVE,

    /** Administrative action. Reversible by an administrator. */
    SUSPENDED,

    /** Automatic, risk driven. Expires on its own or on successful recovery. */
    LOCKED,

    /** Soft deleted. Retained because audit and security data outlive the account (§3.4). */
    DELETED,
    ;

    val isDeleted: Boolean get() = this == DELETED
}

/**
 * The account aggregate.
 *
 * Holds no credential material. Passwords, TOTP secrets and external identities live in their
 * own aggregates so that a user row can be read and cached without touching secrets, and so
 * that an account can exist with no local password at all (concept §8.3, "credential-flexible
 * policy").
 */
data class User(
    val id: UserId,
    val username: Username,
    val primaryEmail: EmailAddress,
    val firstName: String,
    val lastName: String,
    val status: UserStatus,
    val emailVerifiedAt: Instant?,
    val createdAt: Instant,
    val updatedAt: Instant,
    /** Optimistic-locking counter; every write bumps it and asserts the previous value. */
    val version: Long,
) {
    val isEmailVerified: Boolean get() = emailVerifiedAt != null

    val displayName: String
        get() = listOf(firstName, lastName).filter { it.isNotBlank() }.joinToString(" ")
            .ifBlank { username.display }

    /**
     * Maps the account state onto the error that should be returned when this user tries to
     * authenticate, or `null` when the state permits it.
     *
     * [PENDING_EMAIL_VERIFICATION][UserStatus.PENDING_EMAIL_VERIFICATION] is **not** an
     * authentication failure — the user must be able to sign in far enough to resend the
     * verification mail. Individual flows add
     * [EmailVerified][dev.kamiql.helium.flow.requirement] on top where the operation demands it.
     */
    fun toAccessError(): AuthError? = when (status) {
        UserStatus.ACTIVE, UserStatus.PENDING_EMAIL_VERIFICATION -> null
        UserStatus.SUSPENDED -> AuthError.AccountSuspended
        UserStatus.LOCKED -> AuthError.AccountLocked
        // Deleted accounts are indistinguishable from non-existent ones by design.
        UserStatus.DELETED -> AuthError.InvalidCredentials
    }
}

/** Fields an administrator or the account owner may change on a profile. */
data class UserProfileUpdate(
    val username: Username?,
    val firstName: String?,
    val lastName: String?,
)
