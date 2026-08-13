package dev.kamiql.helium.domain.mfa

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.RecoveryCodeId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.UserId
import java.time.Instant

enum class MfaType {
    TOTP,
    WEBAUTHN,
    RECOVERY_CODE,
    ;

    /** Value used in the `methods` array of an `mfa_required` problem response. */
    val token: String get() = name.lowercase()
}

/**
 * A factor is `PENDING` between generating a secret and the user proving they can produce a
 * valid code. Only `ACTIVE` factors count towards MFA policy — concept §4.7: "Store the factor
 * as active only after successful confirmation."
 */
enum class MfaFactorStatus { PENDING, ACTIVE, REVOKED }

data class MfaFactor(
    val id: MfaFactorId,
    val userId: UserId,
    val type: MfaType,
    /** User-chosen label ("iPhone", "Yubikey"). Free text; never used for lookup. */
    val label: String,
    val status: MfaFactorStatus,
    val createdAt: Instant,
    val lastUsedAt: Instant?,
) {
    val isActive: Boolean get() = status == MfaFactorStatus.ACTIVE
}

/**
 * TOTP parameters and the **encrypted** shared secret.
 *
 * Encrypted rather than hashed, because the server must be able to recompute future codes
 * (concept §3.2). [secretKeyVersion] travels with the ciphertext so keys can be rotated and
 * old versions still decrypted (§7.2).
 */
data class TotpFactor(
    val factorId: MfaFactorId,
    val encryptedSecret: ByteArray,
    val secretKeyVersion: Int,
    val algorithm: TotpAlgorithm,
    val digits: Int,
    val periodSeconds: Int,
    /**
     * Highest time step already accepted for this factor.
     *
     * Enforces "one accepted code per time step" (§4.7): a code observed by an attacker on the
     * network cannot be replayed within its own validity window.
     */
    val lastAcceptedStep: Long?,
    val createdAt: Instant,
) {
    // ByteArray in a data class needs structural equality written out.
    override fun equals(other: Any?): Boolean =
        other is TotpFactor && factorId == other.factorId && encryptedSecret.contentEquals(other.encryptedSecret)

    override fun hashCode(): Int = 31 * factorId.hashCode() + encryptedSecret.contentHashCode()

    companion object {
        const val DEFAULT_DIGITS: Int = 6
        const val DEFAULT_PERIOD_SECONDS: Int = 30
        /** Verification window of ±1 step, per concept §4.7. */
        const val DEFAULT_WINDOW_STEPS: Int = 1
        /** Concept §4.7: at least 160 bits of entropy. */
        const val SECRET_BYTES: Int = 20
    }
}

/** SHA-1 remains the interoperability default; SHA-256 only when every client supports it. */
enum class TotpAlgorithm { SHA1, SHA256, SHA512 }

/**
 * A single-use recovery code, stored only as a hash.
 *
 * Shown once at enrollment and never again (concept §3.2).
 */
data class RecoveryCode(
    val id: RecoveryCodeId,
    val userId: UserId,
    val codeHash: String,
    val usedAt: Instant?,
    val createdAt: Instant,
)

/**
 * A short-lived, single-use MFA transaction created when a first factor succeeded but a
 * second is still required.
 *
 * It is *not* a session: it grants nothing except the right to attempt a second factor. The
 * pending outcome (session or authorization code) is materialized only after the challenge
 * is answered.
 */
data class MfaTransaction(
    val id: TransactionId,
    val userId: UserId,
    val availableMethods: Set<MfaType>,
    val createdAt: Instant,
    val expiresAt: Instant,
    val attempts: Int,
    /** Opaque, server-side description of what to do on success. Never sent to the client. */
    val pendingOutcome: String,
) {
    fun isUsable(now: Instant): Boolean = now.isBefore(expiresAt) && attempts < MAX_ATTEMPTS

    companion object {
        /** Concept §4.2: 5-minute MFA transaction. */
        const val LIFETIME_SECONDS: Long = 300
        const val MAX_ATTEMPTS: Int = 5
    }
}

/** When a second factor is demanded. Evaluated per flow, never hardcoded in a route. */
enum class MfaPolicy {
    /** MFA only when the user enrolled a factor. */
    OPTIONAL,

    /** Every user must enroll; login is blocked until they do. */
    REQUIRED,

    /** Required only for accounts holding privileged permissions. */
    REQUIRED_FOR_PRIVILEGED,
}

/**
 * What the user presented to satisfy a second factor.
 *
 * Sealed rather than a bare string because the two families are genuinely different shapes: a
 * TOTP or recovery code is a short value the user typed, while a WebAuthn response is a
 * structured set of authenticator outputs that only means something as a whole. Serializing
 * the latter into the former would put a parser in every implementation and make "which
 * fields are present" a runtime question instead of a compile-time one.
 */
sealed interface MfaResponse {

    /** A value the user typed. Wrapped in [Secret] so it cannot be logged. */
    @JvmInline
    value class Code(val value: Secret) : MfaResponse

    /**
     * Output of `navigator.credentials.create()`, presented to finish enrollment.
     *
     * Every binary field is base64url as it arrived from the client. The bytes are decoded and
     * validated by the WebAuthn adapter, never here — the domain must not grow a CBOR parser.
     */
    data class WebAuthnRegistration(
        val credentialId: String,
        val clientDataJson: String,
        val attestationObject: String,
        /** Authenticator-reported transports (`usb`, `nfc`, `internal`, …). Advisory only. */
        val transports: List<String>,
    ) : MfaResponse

    /**
     * Output of `navigator.credentials.get()`, presented to answer a login challenge.
     *
     * [userHandle] is absent for a non-discoverable credential, which is the normal case for a
     * second factor: the user is already identified by the MFA transaction.
     */
    data class WebAuthnAssertion(
        val credentialId: String,
        val clientDataJson: String,
        val authenticatorData: String,
        val signature: String,
        val userHandle: String?,
    ) : MfaResponse
}

/** Outcome of verifying a second factor. */
sealed interface MfaVerificationResult {
    /** @param acceptedStep the TOTP time step consumed, persisted to block replay. */
    data class Verified(val factorId: MfaFactorId, val acceptedStep: Long?) : MfaVerificationResult
    data object Rejected : MfaVerificationResult
    data object Expired : MfaVerificationResult
}
