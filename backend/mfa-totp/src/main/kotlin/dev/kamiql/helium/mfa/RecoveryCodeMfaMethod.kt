package dev.kamiql.helium.mfa

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.RecoveryCodeId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.TokenHasher
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.RecoveryCode
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.MfaMethod
import java.time.Instant

/**
 * Single-use recovery codes.
 *
 * The escape hatch when the authenticator is lost. Modelled as an [MfaMethod] so the login
 * flow dispatches to it exactly like TOTP and needs no special case.
 *
 * Codes are stored as HMACs, shown once, and consumed atomically. There is no enrollment
 * ceremony: [generate] is called by the TOTP enrollment flow, which is the only moment the
 * plaintext exists.
 */
class RecoveryCodeMfaMethod(
    private val mfaRepository: MfaRepository,
    private val tokenHasher: TokenHasher,
    private val random: RandomSource,
    private val codeCount: Int = DEFAULT_CODE_COUNT,
) : MfaMethod, dev.kamiql.helium.spi.RecoveryCodeIssuer {

    override val type: MfaType = MfaType.RECOVERY_CODE

    /**
     * Generates a fresh set, replacing any existing one.
     *
     * @return the plaintext codes. Display them once; they cannot be recovered afterwards.
     */
    override suspend fun generate(userId: UserId, now: Instant): List<String> {
        val plaintext = List(codeCount) { random.humanCode(groups = 2, groupLength = 5) }
        mfaRepository.replaceRecoveryCodes(
            userId = userId,
            codes = plaintext.map { code ->
                RecoveryCode(
                    id = RecoveryCodeId.random(),
                    userId = userId,
                    codeHash = tokenHasher.hash(normalize(code)),
                    usedAt = null,
                    createdAt = now,
                )
            },
        )
        return plaintext
    }

    /** Recovery codes are issued alongside another factor, never enrolled on their own. */
    override suspend fun beginEnrollment(userId: UserId, now: Instant): EnrollmentChallenge =
        throw UnsupportedOperationException("recovery codes are issued during MFA enrollment")

    override suspend fun confirmEnrollment(
        factorId: MfaFactorId,
        response: MfaResponse,
        now: Instant,
    ): Boolean = false

    /**
     * Consumes a code.
     *
     * The repository call is a conditional UPDATE on `used_at IS NULL`, so the same code
     * presented twice concurrently succeeds at most once.
     */
    override suspend fun verify(userId: UserId, response: MfaResponse, now: Instant): MfaVerificationResult {
        val typed = (response as? MfaResponse.Code) ?: return MfaVerificationResult.Rejected
        val normalized = normalize(typed.value.reveal())
        if (normalized.isEmpty()) return MfaVerificationResult.Rejected

        val consumed = mfaRepository.consumeRecoveryCode(userId, tokenHasher.hash(normalized), now)
        return if (consumed) {
            // No time step to record: a recovery code is inherently single use.
            MfaVerificationResult.Verified(factorId = MfaFactorId.random(), acceptedStep = null)
        } else {
            MfaVerificationResult.Rejected
        }
    }

    override suspend fun isEnrolled(userId: UserId): Boolean =
        mfaRepository.countUnusedRecoveryCodes(userId) > 0

    override suspend fun remaining(userId: UserId): Int = mfaRepository.countUnusedRecoveryCodes(userId)

    /**
     * Users retype these from paper, so grouping dashes, spaces and case are all forgiven.
     * The lookup hash is computed over the normalized form on both write and read.
     */
    private fun normalize(code: String): String =
        code.uppercase().filter { it.isLetterOrDigit() }

    companion object {
        const val DEFAULT_CODE_COUNT: Int = 10
    }
}
