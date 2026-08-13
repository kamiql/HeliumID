package dev.kamiql.helium.spi

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions
import dev.kamiql.helium.domain.mfa.WebAuthnRegistrationOptions
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

    /**
     * Issues the server-chosen nonce this method's [verify] will expect.
     *
     * `null` for methods whose response is a value the user reads off a screen or a printed
     * sheet — there is nothing for the server to choose, so there is nothing to hand out.
     * WebAuthn overrides it: an assertion is a signature *over* a challenge, and a challenge
     * the client picked would prove nothing.
     *
     * Implementations must store the challenge for exactly one redemption and scope it to
     * [userId], so an assertion collected for one account cannot be replayed against another.
     */
    suspend fun beginVerification(userId: UserId, now: Instant): VerificationChallenge? = null

    /** Verifies a challenge response during login or step-up. */
    suspend fun verify(userId: UserId, response: MfaResponse, now: Instant): MfaVerificationResult

    /** Whether the user has an active factor of this type. */
    suspend fun isEnrolled(userId: UserId): Boolean
}

/**
 * What the client needs in order to complete enrollment.
 *
 * Sealed because the shapes have nothing in common beyond the factor they belong to: TOTP
 * hands over a shared secret, WebAuthn hands over creation options and keeps every secret on
 * the authenticator. A single record carrying both sets of fields would leave half of them
 * meaningless — and nullable — in either case.
 */
sealed interface EnrollmentChallenge {

    val factorId: MfaFactorId
    val type: MfaType

    /**
     * @param secret displayed once, for manual entry.
     * @param provisioningUri `otpauth://` URI the client renders as a QR code.
     */
    data class Totp(
        override val factorId: MfaFactorId,
        val secret: String,
        val provisioningUri: String,
    ) : EnrollmentChallenge {
        override val type: MfaType get() = MfaType.TOTP
    }

    /** Creation options for `navigator.credentials.create()`. Carries no secret. */
    data class WebAuthn(
        override val factorId: MfaFactorId,
        val options: WebAuthnRegistrationOptions,
    ) : EnrollmentChallenge {
        override val type: MfaType get() = MfaType.WEBAUTHN
    }
}

/**
 * A nonce the client must sign, issued between login and [MfaMethod.verify].
 *
 * Only WebAuthn needs one today; the type is sealed so a future method that also signs a
 * challenge extends it rather than reusing this one's fields for something else.
 */
sealed interface VerificationChallenge {

    val type: MfaType

    /** Request options for `navigator.credentials.get()`. */
    data class WebAuthn(val options: WebAuthnAuthenticationOptions) : VerificationChallenge {
        override val type: MfaType get() = MfaType.WEBAUTHN
    }
}

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
