package dev.kamiql.helium.mfa

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Recovery codes: the escape hatch when the authenticator is gone.
 *
 * The properties that matter are all about *what is left behind*. A code must survive exactly one
 * use, must never be stored in a form that reads back, must not authenticate a different account,
 * and regenerating must replace the old set rather than add to it — a set that grows is a set that
 * never really gets revoked.
 */
class RecoveryCodeMfaMethodTest {

    private val userId = UserId.random()
    private val other = UserId.random()
    private val now: Instant = Instant.ofEpochSecond(1_700_000_000)

    private val repository = InMemoryMfaRepository()
    private val hasher = tokenHasher()

    private fun method(codeCount: Int = RecoveryCodeMfaMethod.DEFAULT_CODE_COUNT) = RecoveryCodeMfaMethod(
        mfaRepository = repository,
        tokenHasher = hasher,
        random = FixedSecretRandomSource(),
        codeCount = codeCount,
    )

    private fun response(value: String) = MfaResponse.Code(Secret.of(value))

    @Test
    fun `generation issues the configured number of codes and reports them as enrolled`() = runTest {
        val method = method(codeCount = 4)

        val codes = method.generate(userId, now)

        assertEquals(4, codes.size)
        assertEquals(4, method.remaining(userId))
        assertTrue(method.isEnrolled(userId))
        assertFalse(method.isEnrolled(other))
    }

    @Test
    fun `codes are stored hashed, never in a form that reads back`() = runTest {
        val codes = method().generate(userId, now)

        val stored = repository.listRecoveryCodes(userId).map { it.codeHash }
        // Not just "different from the plaintext" — the normalized code must not be recoverable
        // from the row at all, which is what a keyed hash buys over an encoding.
        codes.forEach { code ->
            val normalized = code.uppercase().filter(Char::isLetterOrDigit)
            assertFalse(stored.any { it.contains(normalized, ignoreCase = true) })
        }
        assertEquals(codes.size, stored.distinct().size, "each code must hash to its own row")
    }

    @Test
    fun `a code works once and is refused the second time`() = runTest {
        val method = method()
        val code = method.generate(userId, now).first()

        assertIs<MfaVerificationResult.Verified>(method.verify(userId, response(code), now))
        // The conditional UPDATE on `used_at IS NULL` is the whole mechanism: without it a code
        // read off a printout stays valid forever.
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(code), now))
        assertEquals(RecoveryCodeMfaMethod.DEFAULT_CODE_COUNT - 1, method.remaining(userId))
    }

    @Test
    fun `one account's code cannot authenticate another`() = runTest {
        val method = method()
        val theirs = method.generate(other, now).first()
        method.generate(userId, now)

        // The repository predicate is scoped to the user for exactly this reason: a hash resolved
        // globally would turn any leaked code into a key for every account.
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(theirs), now))
        assertEquals(RecoveryCodeMfaMethod.DEFAULT_CODE_COUNT, method.remaining(other))
    }

    @Test
    fun `grouping, case and spacing are forgiven because these are retyped from paper`() = runTest {
        val method = method()
        val code = method.generate(userId, now).first()

        val mangled = code.lowercase().replace("-", " ").let { " $it " }
        assertIs<MfaVerificationResult.Verified>(method.verify(userId, response(mangled), now))
    }

    @Test
    fun `an empty or wrongly typed response is refused`() = runTest {
        val method = method()
        method.generate(userId, now)

        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(""), now))
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response("---"), now))
        assertEquals(
            MfaVerificationResult.Rejected,
            method.verify(userId, MfaResponse.WebAuthnAssertion("id", "{}", "auth", "sig", null), now),
        )
        assertEquals(RecoveryCodeMfaMethod.DEFAULT_CODE_COUNT, method.remaining(userId))
    }

    @Test
    fun `regenerating replaces the previous set rather than adding to it`() = runTest {
        val method = method()
        val first = method.generate(userId, now)

        val second = method.generate(userId, now.plusSeconds(60))

        assertEquals(2, repository.recoveryCodeReplacements)
        assertEquals(RecoveryCodeMfaMethod.DEFAULT_CODE_COUNT, method.remaining(userId))
        // "Regenerate" is how a user revokes a set they think leaked. If the old codes survived,
        // the action would report success while changing nothing that matters.
        assertEquals(MfaVerificationResult.Rejected, method.verify(userId, response(first.first()), now))
        assertIs<MfaVerificationResult.Verified>(method.verify(userId, response(second.first()), now))
    }

    @Test
    fun `there is no standalone enrollment ceremony`() = runTest {
        val method = method()

        // Codes are issued alongside a real factor. An enrollment endpoint of their own would be
        // a way to obtain a second factor without ever proving possession of anything.
        assertFailsWith<UnsupportedOperationException> { method.beginEnrollment(userId, now) }
        assertFalse(method.confirmEnrollment(MfaFactorId.random(), response("whatever"), now))
        assertEquals(MfaType.RECOVERY_CODE, method.type)
    }
}
