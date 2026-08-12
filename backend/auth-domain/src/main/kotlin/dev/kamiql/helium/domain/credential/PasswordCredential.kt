package dev.kamiql.helium.domain.credential

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.UserId
import java.time.Instant

/**
 * A stored password hash plus the parameters it was produced with.
 *
 * Parameters are persisted per credential rather than read from configuration so that raising
 * the cost factor does not invalidate existing hashes: verification uses the stored
 * parameters, and [PasswordHasher.needsRehash] tells the login flow to transparently upgrade
 * the hash while the plaintext is briefly available.
 */
data class PasswordCredential(
    val userId: UserId,
    val hash: PasswordHash,
    val changedAt: Instant,
    val createdAt: Instant,
)

/**
 * An encoded password hash.
 *
 * @param algorithm always `argon2id` for new credentials; older values are kept so legacy
 *        hashes can still be verified and upgraded.
 * @param encoded the full encoded hash including salt, in the algorithm's own format. This is
 *        a [String] rather than a [Secret] because it is not usable as a credential — but it
 *        is still classified data and must not be logged or returned by any API.
 */
data class PasswordHash(
    val algorithm: String,
    val encoded: String,
    val parameters: PasswordHashParameters,
) {
    override fun toString(): String = "PasswordHash($algorithm, redacted)"
}

/** Argon2id cost parameters. Concept §4.1 starting point: 64 MiB, t=3, p=1–2. */
data class PasswordHashParameters(
    val memoryKib: Int,
    val iterations: Int,
    val parallelism: Int,
    val saltLength: Int,
    val hashLength: Int,
    /** Version of the server-side pepper used, so the pepper can be rotated. */
    val pepperVersion: Int,
) {
    companion object {
        /**
         * Starting values from concept §4.1. They target 100–300 ms per verification and
         * **must** be benchmarked in the deployment environment
         * (`HELIUM_ARGON2_*` environment variables override them).
         */
        val DEFAULT: PasswordHashParameters = PasswordHashParameters(
            memoryKib = 64 * 1024,
            iterations = 3,
            parallelism = 2,
            saltLength = 16,
            hashLength = 32,
            pepperVersion = 1,
        )
    }
}

/**
 * Port for password hashing. Implemented in `security-crypto` on top of an audited Argon2id
 * implementation — CLAUDE.md forbids inventing cryptography.
 */
interface PasswordHasher {

    /** Hashes [password] with the current configured parameters. */
    suspend fun hash(password: Secret): PasswordHash

    /**
     * Verifies [password] against [hash] in constant time with respect to the hash contents.
     */
    suspend fun verify(password: Secret, hash: PasswordHash): Boolean

    /**
     * Burns roughly the same CPU and memory as a real [verify] and always returns `false`.
     *
     * Called when no account matched, so that a missing account and a wrong password take
     * indistinguishable time. Concept §2.6: "Use a dummy Argon2id verification path if the
     * account does not exist."
     */
    suspend fun verifyDummy(password: Secret): Boolean

    /** True when [hash] was produced with weaker parameters than the current configuration. */
    fun needsRehash(hash: PasswordHash): Boolean
}

/**
 * Password policy from concept §4.1: length bounds and a breach check, deliberately **no**
 * composition rules.
 */
data class PasswordPolicy(
    val minLength: Int = 12,
    val maxLength: Int = 256,
    val rejectBreached: Boolean = true,
    /** Rejects passwords containing the username or the local part of the email. */
    val rejectContainsIdentifier: Boolean = true,
) {
    companion object {
        val DEFAULT: PasswordPolicy = PasswordPolicy()
    }
}

/** Outcome of evaluating [PasswordPolicy]. Reasons are stable, non-sensitive tokens. */
sealed interface PasswordPolicyResult {
    data object Acceptable : PasswordPolicyResult
    data class Rejected(val reasons: List<PasswordRejectionReason>) : PasswordPolicyResult
}

enum class PasswordRejectionReason {
    TOO_SHORT,
    TOO_LONG,
    BREACHED,
    CONTAINS_IDENTIFIER,
    ;

    /** Lowercase token used in the `validation_failed` problem payload. */
    val token: String get() = name.lowercase()
}

/**
 * Port for a breached-password check (k-anonymity range query, or a local bloom filter).
 *
 * Implementations must fail **open** — a password checker outage should not block every
 * registration — but must record the degradation. Availability of this control is not a
 * security boundary; the length policy is.
 */
interface BreachedPasswordChecker {
    suspend fun isBreached(password: Secret): Boolean

    /** Never rejects. Used in tests and when no checker is configured. */
    object Disabled : BreachedPasswordChecker {
        override suspend fun isBreached(password: Secret): Boolean = false
    }
}
