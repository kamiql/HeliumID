package dev.kamiql.helium.mfa

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.TotpFactor
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.samstevens.totp.code.DefaultCodeGenerator
import dev.samstevens.totp.code.HashingAlgorithm
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The TOTP adapter, driven through its ports.
 *
 * Two of these tests are the reason the suite exists. *A spent code is refused* is the replay
 * guard from concept §4.7, and it is invisible to any test that checks a correct code only once.
 * *Malformed input never decrypts* is the cheap-rejection property: without it a flood of
 * six-letter garbage turns into a KMS bill.
 *
 * The secret is pinned to RFC 6238's Appendix B seed, so the expected codes come from the
 * standard rather than from this codebase agreeing with itself.
 */
class TotpMfaMethodTest {

    private val userId = UserId.random()
    private val now: Instant = Instant.ofEpochSecond(1_700_000_000)
    private val period = TotpFactor.DEFAULT_PERIOD_SECONDS.toLong()

    private val repository = InMemoryMfaRepository()
    private val cipher = CountingSecretCipher(secretCipher(1))

    /** [MfaMethod.beginEnrollment] is typed to the interface; a TOTP enrollment must answer with this. */
    private suspend fun TotpMfaMethod.totpEnrollment(at: Instant) =
        assertIs<EnrollmentChallenge.Totp>(beginEnrollment(userId, at))

    private fun method(windowSteps: Int = TotpFactor.DEFAULT_WINDOW_STEPS) = TotpMfaMethod(
        mfaRepository = repository,
        users = userRepositoryFor(userId),
        cipher = cipher,
        random = FixedSecretRandomSource(),
        issuerLabel = "Helium ID",
        windowSteps = windowSteps,
    )

    /** What an authenticator app would show at [at], computed the way RFC 6238 prescribes. */
    private fun code(at: Instant): String =
        DefaultCodeGenerator(HashingAlgorithm.SHA1, TotpFactor.DEFAULT_DIGITS)
            .generate(FixedSecretRandomSource.RFC_6238_SHA1_SECRET_BASE32, at.epochSecond / period)

    private fun response(value: String) = MfaResponse.Code(Secret.of(value))

    private fun step(at: Instant) = at.epochSecond / period

    // --- enrollment ---------------------------------------------------------------------

    @Test
    fun `enrollment issues the RFC 6238 secret and leaves the factor pending`() = runTest {
        val challenge = method().totpEnrollment(now)

        assertEquals(FixedSecretRandomSource.RFC_6238_SHA1_SECRET_BASE32, challenge.secret)
        // PENDING until a code proves the user actually scanned it: activating first would mean
        // a mis-scanned secret locks the account out of its own second factor.
        assertEquals(MfaFactorStatus.PENDING, repository.findFactor(challenge.factorId)?.status)
        assertFalse(method().isEnrolled(userId))
    }

    @Test
    fun `the provisioning uri carries the secret and the issuer, url encoded`() = runTest {
        val challenge = method().totpEnrollment(now)

        assertTrue(challenge.provisioningUri.startsWith("otpauth://totp/"))
        // `issuer:account`, each half encoded but the separator left alone — that colon is
        // structure in the Key Uri Format, and encoding it makes apps show one nameless entry.
        assertTrue(challenge.provisioningUri.contains("/Helium+ID:ada%40example.com?"))
        assertTrue(challenge.provisioningUri.contains("issuer=Helium+ID"))
        assertTrue(challenge.provisioningUri.contains("secret=${challenge.secret}"))
        assertTrue(challenge.provisioningUri.contains("digits=${TotpFactor.DEFAULT_DIGITS}"))
        assertTrue(challenge.provisioningUri.contains("period=${TotpFactor.DEFAULT_PERIOD_SECONDS}"))
    }

    @Test
    fun `the stored secret is ciphertext, not the base32 the user scanned`() = runTest {
        val challenge = method().totpEnrollment(now)

        val row = assertNotNull(repository.findTotp(challenge.factorId))
        val stored = String(row.encryptedSecret, Charsets.UTF_8)
        assertFalse(
            stored.contains(FixedSecretRandomSource.RFC_6238_SHA1_SECRET_BASE32),
            "concept §3.2: the secret is encrypted at rest, so it must not appear in the row",
        )
    }

    @Test
    fun `restarting enrollment revokes the half-configured factor`() = runTest {
        val first = method().beginEnrollment(userId, now)
        val second = method().beginEnrollment(userId, now)

        assertNotEquals(first.factorId, second.factorId)
        // Otherwise the abandoned secret stays activatable, and a code captured during the first,
        // abandoned setup could still enrol a factor afterwards.
        assertEquals(MfaFactorStatus.REVOKED, repository.findFactor(first.factorId)?.status)
        assertEquals(MfaFactorStatus.PENDING, repository.findFactor(second.factorId)?.status)
    }

    @Test
    fun `confirmation activates the factor and a wrong code does not`() = runTest {
        val method = method()
        val challenge = method.beginEnrollment(userId, now)

        assertFalse(method.confirmEnrollment(challenge.factorId, response("000000"), now))
        assertEquals(MfaFactorStatus.PENDING, repository.findFactor(challenge.factorId)?.status)

        assertTrue(method.confirmEnrollment(challenge.factorId, response(code(now)), now))
        assertEquals(MfaFactorStatus.ACTIVE, repository.findFactor(challenge.factorId)?.status)
        assertTrue(method.isEnrolled(userId))
    }

    @Test
    fun `an already active factor cannot be confirmed a second time`() = runTest {
        val method = method()
        val challenge = enrolled(method)

        // The status guard is what stops a replayed enrollment request from touching an account
        // that is already set up.
        val later = now.plusSeconds(period)
        assertFalse(method.confirmEnrollment(challenge.factorId, response(code(later)), later))
    }

    // --- verification -------------------------------------------------------------------

    @Test
    fun `a current code verifies and reports the step it consumed`() = runTest {
        val method = method()
        val challenge = enrolled(method)

        val result = assertIs<MfaVerificationResult.Verified>(method.verify(userId, response(code(now)), now))
        assertEquals(challenge.factorId, result.factorId)
        assertEquals(step(now), result.acceptedStep)
        assertEquals(now, repository.findFactor(challenge.factorId)?.lastUsedAt)
    }

    @Test
    fun `a spent code is refused when it is presented again`() = runTest {
        val method = method()
        enrolled(method)

        val current = code(now)
        assertIs<MfaVerificationResult.Verified>(method.verify(userId, response(current), now))

        // The whole point: a code observed on the wire stays valid for the rest of its 30-second
        // window unless the consumed step is recorded. The answer is `Rejected` rather than a
        // distinct "replayed", so an attacker cannot tell a burned code from a wrong one.
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(current), now))
    }

    @Test
    fun `an earlier step is refused once a later one has been accepted`() = runTest {
        val method = method()
        enrolled(method)

        val later = now.plusSeconds(period)
        assertIs<MfaVerificationResult.Verified>(method.verify(userId, response(code(later)), later))

        // Still inside the ±1-step drift window, so only the monotonic counter rejects it.
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(code(now)), later))
    }

    @Test
    fun `clock drift of one step in either direction is tolerated`() = runTest {
        val method = method()
        enrolled(method)

        // The phone runs a step slow, then a step fast. Both are accepted — and in this order,
        // because the consumed step only ever moves forward.
        assertIs<MfaVerificationResult.Verified>(
            method.verify(userId, response(code(now.minusSeconds(period))), now),
        )
        assertIs<MfaVerificationResult.Verified>(
            method.verify(userId, response(code(now.plusSeconds(period))), now),
        )
    }

    @Test
    fun `a code two steps away is outside the window`() = runTest {
        val method = method()
        enrolled(method)

        // Not blocked by the replay counter — this step is newer than the enrolled one — so the
        // rejection is the drift window doing its job.
        val twoStepsAgo = now.minusSeconds(2 * period)
        assertTrue(step(twoStepsAgo) > enrolledStep, "the window, not the counter, must reject this")
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(code(twoStepsAgo)), now))
    }

    @Test
    fun `verification fails when no active factor exists`() = runTest {
        val method = method()
        method.beginEnrollment(userId, now) // pending, never confirmed

        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(code(now)), now))
        assertEquals(MfaVerificationResult.Rejected, method.verify(UserId.random(), response(code(now)), now))
    }

    // --- cheap rejection ----------------------------------------------------------------

    @Test
    fun `malformed input is refused without decrypting the secret`() = runTest {
        val method = method()
        enrolled(method)
        val baseline = cipher.decryptions

        // Wrong length, non-digits, empty, and the wrong ceremony's output entirely. Each must
        // lose on shape alone — reaching the cipher would make this endpoint an amplifier.
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response("12345"), now))
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response("abcdef"), now))
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(""), now))
        assertEquals(
            MfaVerificationResult.Rejected,
            method.verify(userId, MfaResponse.WebAuthnAssertion("id", "{}", "auth", "sig", null), now),
        )

        assertEquals(baseline, cipher.decryptions, "malformed input must not reach the cipher")
    }

    @Test
    fun `surrounding whitespace is forgiven, because users paste`() = runTest {
        val method = method()
        enrolled(method)

        assertIs<MfaVerificationResult.Verified>(method.verify(userId, response("  ${code(now)} "), now))
    }

    /**
     * The step burned by [enrolled]. Confirmation consumes one, so every verification test has to
     * present something newer — set well back so the drift cases are not fighting the counter.
     */
    private val enrolledAt: Instant get() = now.minusSeconds(10 * period)
    private val enrolledStep: Long get() = step(enrolledAt)

    /** Enrolls and activates a factor, returning the challenge that created it. */
    private suspend fun enrolled(method: TotpMfaMethod) = method.totpEnrollment(enrolledAt).also {
        check(method.confirmEnrollment(it.factorId, response(code(enrolledAt)), enrolledAt)) {
            "test setup failed: the factor was not activated"
        }
    }
}
