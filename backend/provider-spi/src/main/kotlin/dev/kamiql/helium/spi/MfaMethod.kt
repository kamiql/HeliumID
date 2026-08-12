package dev.kamiql.helium.spi

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import java.time.Instant

/**
 * A second-factor method.
 *
 * Concept §1.3: "New MFA methods should implement this interface without changing registration
 * or login domain logic." Adding WebAuthn later means adding an implementation and registering
 * it — the login flow already asks the registry which methods a user has and dispatches to
 * whichever answered.
 */
interface MfaMethod {

    val type: MfaType

    /**
     * Creates a factor in `PENDING` state and returns what the user needs to set it up.
     *
     * The factor must not count towards MFA policy until [confirmEnrollment] succeeds:
     * activating on generation would let a user lock themselves out with a secret they never
     * managed to scan (concept §4.7).
     */
    suspend fun beginEnrollment(userId: UserId, now: Instant): EnrollmentChallenge

    /** Proves the user can produce a valid response, and activates the factor. */
    suspend fun confirmEnrollment(factorId: MfaFactorId, response: MfaResponse, now: Instant): Boolean

    /** Verifies a challenge response during login or step-up. */
    suspend fun verify(userId: UserId, response: MfaResponse, now: Instant): MfaVerificationResult

    /** Whether the user has an active factor of this type. */
    suspend fun isEnrolled(userId: UserId): Boolean
}

/**
 * @param secret displayed once, for manual entry.
 * @param provisioningUri `otpauth://` URI the client renders as a QR code.
 */
data class EnrollmentChallenge(
    val factorId: MfaFactorId,
    val type: MfaType,
    val secret: String,
    val provisioningUri: String,
)

/**
 * Registry of the configured methods.
 *
 * The login flow consults this rather than referring to TOTP by name, which is what keeps
 * "which factors exist" out of the flow definitions.
 */
class MfaMethodRegistry(methods: List<MfaMethod>) {

    private val byType = methods.associateBy { it.type }

    operator fun get(type: MfaType): MfaMethod? = byType[type]

    val types: Set<MfaType> get() = byType.keys

    /** Which methods this user could actually complete right now. */
    suspend fun enrolledMethods(userId: UserId): Set<MfaType> =
        byType.values.filter { it.isEnrolled(userId) }.map { it.type }.toSet()
}

/**
 * Issues recovery codes.
 *
 * Separate from [MfaMethod] because recovery codes are generated as a side effect of enrolling
 * a real factor rather than enrolled themselves — and because the enrollment flow needs the
 * plaintext, which no [MfaMethod] method returns.
 */
interface RecoveryCodeIssuer {

    /**
     * Replaces the user's codes and returns the new plaintext set.
     *
     * The caller must show them exactly once. They are stored hashed and cannot be recovered.
     */
    suspend fun generate(userId: UserId, now: Instant): List<String>

    suspend fun remaining(userId: UserId): Int
}
