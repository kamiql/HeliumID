package dev.kamiql.helium.mfa

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.EncryptedSecret
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.SecretCipher
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.TotpAlgorithm
import dev.kamiql.helium.domain.mfa.TotpFactor
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.MfaMethod
import dev.samstevens.totp.code.DefaultCodeGenerator
import dev.samstevens.totp.code.HashingAlgorithm
import org.apache.commons.codec.binary.Base32
import org.slf4j.LoggerFactory
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/**
 * TOTP (RFC 6238) second factor.
 *
 * Code generation comes from `dev.samstevens.totp`; this class owns only what concept §6.5
 * says the application must own — secret generation, secret storage, and the verification
 * window and replay policy.
 *
 * Two properties are worth calling out because they are easy to get wrong:
 *
 *  * **Secrets are encrypted, not hashed** (§3.2). The server has to recompute future codes,
 *    so a one-way function is not an option. The key lives in the KMS-backed [SecretCipher]
 *    and its version is stored alongside the ciphertext so keys can rotate.
 *  * **A code is accepted at most once** (§4.7). Verification succeeds only if the matched
 *    time step is strictly greater than the last accepted one, enforced by a conditional
 *    UPDATE. Without it, a code observed on the network stays replayable for its whole
 *    30-second window.
 *
 * @param issuerLabel shown in the authenticator app; usually the deployment's brand name.
 */
class TotpMfaMethod(
    private val mfaRepository: MfaRepository,
    private val users: UserRepository,
    private val cipher: SecretCipher,
    private val random: RandomSource,
    private val issuerLabel: String,
    private val windowSteps: Int = TotpFactor.DEFAULT_WINDOW_STEPS,
) : MfaMethod {

    private val log = LoggerFactory.getLogger(TotpMfaMethod::class.java)
    private val base32 = Base32()
    private val codeGenerator = DefaultCodeGenerator(HashingAlgorithm.SHA1, TotpFactor.DEFAULT_DIGITS)

    override val type: MfaType = MfaType.TOTP

    override suspend fun beginEnrollment(userId: UserId, now: Instant): EnrollmentChallenge {
        val user = users.findById(userId) ?: error("cannot enroll TOTP for unknown user")

        // Any pending enrollment is discarded: restarting setup must not leave a second,
        // half-configured secret behind that could later be activated.
        mfaRepository.listFactors(userId)
            .filter { it.type == MfaType.TOTP && it.status == MfaFactorStatus.PENDING }
            .forEach { mfaRepository.revokeFactor(it.id, now) }

        val secretBytes = random.bytes(TotpFactor.SECRET_BYTES)
        val secretBase32 = base32.encodeAsString(secretBytes).trimEnd('=')

        val factor = MfaFactor(
            id = MfaFactorId.random(),
            userId = userId,
            type = MfaType.TOTP,
            label = "Authenticator app",
            // PENDING until the user proves they can produce a code (§4.7).
            status = MfaFactorStatus.PENDING,
            createdAt = now,
            lastUsedAt = null,
        )
        mfaRepository.insertFactor(factor)

        val encrypted = cipher.encrypt(secretBase32.toByteArray(StandardCharsets.UTF_8))
        mfaRepository.insertTotp(
            TotpFactor(
                factorId = factor.id,
                encryptedSecret = encrypted.encode().toByteArray(StandardCharsets.UTF_8),
                secretKeyVersion = encrypted.keyVersion,
                algorithm = TotpAlgorithm.SHA1,
                digits = TotpFactor.DEFAULT_DIGITS,
                periodSeconds = TotpFactor.DEFAULT_PERIOD_SECONDS,
                lastAcceptedStep = null,
                createdAt = now,
            ),
        )

        return EnrollmentChallenge(
            factorId = factor.id,
            type = MfaType.TOTP,
            secret = secretBase32,
            provisioningUri = provisioningUri(secretBase32, user.primaryEmail.display),
        )
    }

    override suspend fun confirmEnrollment(
        factorId: MfaFactorId,
        response: MfaResponse,
        now: Instant,
    ): Boolean {
        val factor = mfaRepository.findFactor(factorId) ?: return false
        if (factor.type != MfaType.TOTP || factor.status != MfaFactorStatus.PENDING) return false

        val totp = mfaRepository.findTotp(factorId) ?: return false
        val matchedStep = matchStep(totp, response, now) ?: return false

        if (!mfaRepository.tryAdvanceTotpStep(factorId, matchedStep)) return false
        mfaRepository.activateFactor(factorId, now)
        return true
    }

    override suspend fun verify(userId: UserId, response: MfaResponse, now: Instant): MfaVerificationResult {
        val factor = mfaRepository.findActiveFactorOfType(userId, MfaType.TOTP)
            ?: return MfaVerificationResult.Rejected
        val totp = mfaRepository.findTotp(factor.id) ?: return MfaVerificationResult.Rejected

        val matchedStep = matchStep(totp, response, now) ?: return MfaVerificationResult.Rejected

        // Replay guard. A correct code that was already spent is rejected exactly like a wrong
        // one: the attacker learns nothing from the difference.
        if (!mfaRepository.tryAdvanceTotpStep(factor.id, matchedStep)) {
            log.warn("rejected a replayed TOTP time step for factor {}", factor.id)
            return MfaVerificationResult.Rejected
        }

        mfaRepository.touchFactor(factor.id, now)
        return MfaVerificationResult.Verified(factor.id, matchedStep)
    }

    override suspend fun isEnrolled(userId: UserId): Boolean =
        mfaRepository.findActiveFactorOfType(userId, MfaType.TOTP) != null

    /**
     * Returns the time step the supplied code matches, or `null`.
     *
     * Checks ±[windowSteps] around now to tolerate clock drift, and compares in constant time
     * so the loop does not leak which step matched through timing.
     */
    private fun matchStep(totp: TotpFactor, response: MfaResponse, now: Instant): Long? {
        val secret = decryptSecret(totp) ?: return null
        val currentStep = now.epochSecond / totp.periodSeconds
        val supplied = response.code.reveal().trim()
        if (supplied.length != totp.digits || supplied.any { !it.isDigit() }) return null

        var matched: Long? = null
        for (offset in -windowSteps..windowSteps) {
            val candidateStep = currentStep + offset
            val expected = runCatching { codeGenerator.generate(secret, candidateStep) }.getOrNull() ?: continue
            if (constantTimeEquals(expected, supplied) && matched == null) {
                matched = candidateStep
            }
        }
        return matched
    }

    private fun decryptSecret(totp: TotpFactor): String? {
        val encoded = String(totp.encryptedSecret, StandardCharsets.UTF_8)
        val encrypted = EncryptedSecret.decode(encoded) ?: return null
        return runCatching { String(cipher.decrypt(encrypted), StandardCharsets.UTF_8) }
            .onFailure { log.error("failed to decrypt TOTP secret for factor {}", totp.factorId, it) }
            .getOrNull()
    }

    private fun constantTimeEquals(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(StandardCharsets.UTF_8), b.toByteArray(StandardCharsets.UTF_8))

    /**
     * `otpauth://` URI for the authenticator app.
     *
     * Returned to the client, which renders the QR code. Generating the image server side would
     * mean the secret travels through an image encoder and, more importantly, through whatever
     * caches sit in front of the response.
     */
    private fun provisioningUri(secretBase32: String, account: String): String {
        fun encode(value: String) = URLEncoder.encode(value, StandardCharsets.UTF_8)
        return "otpauth://totp/${encode(issuerLabel)}:${encode(account)}" +
            "?secret=$secretBase32" +
            "&issuer=${encode(issuerLabel)}" +
            "&algorithm=SHA1" +
            "&digits=${TotpFactor.DEFAULT_DIGITS}" +
            "&period=${TotpFactor.DEFAULT_PERIOD_SECONDS}"
    }
}
