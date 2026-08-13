package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import dev.kamiql.helium.flow.FlowResult
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The passkey half of MFA: fetching a login challenge, and enrolling and removing credentials.
 *
 * The flows are the real ones; only the adapters underneath are fakes. What is being tested is
 * the policy those flow definitions encode — who may call them, what a failure reveals, and what
 * else changes as a side effect — none of which survives being stubbed out.
 */
class MfaChallengeTest {

    /**
     * The regression this whole flow exists to prevent.
     *
     * `beginMfaChallenge` peeks the transaction. If it ever consumed it, asking for the nonce
     * needed to answer the challenge would spend the single attempt the user has, and no passkey
     * sign-in could ever complete.
     */
    @Test
    fun `fetching a challenge does not consume the mfa transaction`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser("ada")

        val challenge = assertIs<FlowResult.Challenge>(fixture.login("ada"))

        // Twice, because a store that deleted on read would still pass a single call.
        assertIs<FlowResult.Success<MfaChallengeStarted>>(fixture.beginMfaChallenge(challenge.transactionId))
        assertIs<FlowResult.Success<MfaChallengeStarted>>(fixture.beginMfaChallenge(challenge.transactionId))

        assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.completeMfa(challenge.transactionId, rememberDevice = false),
        )
    }

    /** TOTP has no server-chosen nonce, so "nothing to hand out" is a success, not an error. */
    @Test
    fun `a method with nothing to hand out succeeds with no options`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser("ada")
        val challenge = assertIs<FlowResult.Challenge>(fixture.login("ada"))

        val started = assertIs<FlowResult.Success<MfaChallengeStarted>>(
            fixture.beginMfaChallenge(challenge.transactionId, MfaType.TOTP),
        )

        assertEquals(MfaType.TOTP, started.value.method)
        assertNull(started.value.webauthnOptions)
    }

    @Test
    fun `a webauthn challenge carries the options the authenticator must sign`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val userId = fixture.createUser("ada")
        fixture.seedPasskey(userId)

        val challenge = assertIs<FlowResult.Challenge>(fixture.login("ada"))
        val started = assertIs<FlowResult.Success<MfaChallengeStarted>>(
            fixture.beginMfaChallenge(challenge.transactionId, MfaType.WEBAUTHN),
        )

        val options = assertNotNull(started.value.webauthnOptions)
        assertEquals(PASSKEY_RP_ID, options.rpId)
        // Named rather than discoverable: the user is already identified by the transaction,
        // and naming the credential keeps non-discoverable security keys working.
        assertEquals(listOf(PASSKEY_CREDENTIAL_ID), options.allowCredentialIds)
    }

    /** The assertion path runs end to end, proving `completeMfa` is no longer TOTP-shaped. */
    @Test
    fun `an assertion completes the login the challenge started`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val userId = fixture.createUser("ada")
        fixture.seedPasskey(userId)

        val challenge = assertIs<FlowResult.Challenge>(fixture.login("ada"))
        fixture.beginMfaChallenge(challenge.transactionId, MfaType.WEBAUTHN)

        val success = assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.completeMfa(
                challenge.transactionId,
                rememberDevice = false,
                method = MfaType.WEBAUTHN,
                response = passkeyAssertion(),
            ),
        )
        assertEquals(userId, success.value.userId)
    }

    /**
     * A handle that never existed and one that expired must be indistinguishable, or the
     * endpoint becomes an oracle for which transactions are live.
     */
    @Test
    fun `an unknown transaction is reported as expired`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser("ada")

        val failure = assertIs<FlowResult.Failure>(
            fixture.beginMfaChallenge(TransactionId("mfa_does_not_exist"), MfaType.WEBAUTHN),
        )
        assertEquals(AuthError.MfaExpired, failure.error)
    }

    private fun passkeyAssertion(): MfaResponse.WebAuthnAssertion = MfaResponse.WebAuthnAssertion(
        credentialId = PASSKEY_CREDENTIAL_ID,
        clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
        authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4",
        signature = "MEUCIQ",
        userHandle = null,
    )
}

class WebAuthnEnrollmentTest {

    /**
     * The deliberate difference from TOTP.
     *
     * Several authenticators per account is the point of passkeys, and the recovery story rests
     * on registering a second one before the first is lost.
     */
    @Test
    fun `a second passkey may be enrolled while the first is active`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        fixture.enrollPasskey(ada)

        val second = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))
        assertIs<FlowResult.Success<WebAuthnEnrollmentConfirmed>>(
            fixture.confirmEnrollment(ada, second.value.factorId),
        )

        assertEquals(2, fixture.mfaRepository.rows().count { it.isActive })
    }

    /**
     * Regenerating on every enrollment would silently invalidate the sheet a user already wrote
     * down — discovered at the worst possible moment, when they reach for it.
     */
    @Test
    fun `recovery codes are issued for the first factor only`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")

        val first = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))
        val firstConfirmed = assertIs<FlowResult.Success<WebAuthnEnrollmentConfirmed>>(
            fixture.confirmEnrollment(ada, first.value.factorId),
        )
        assertEquals(8, assertNotNull(firstConfirmed.value.recoveryCodes).size)

        val second = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))
        val secondConfirmed = assertIs<FlowResult.Success<WebAuthnEnrollmentConfirmed>>(
            fixture.confirmEnrollment(ada, second.value.factorId),
        )
        assertNull(secondConfirmed.value.recoveryCodes)

        assertEquals(1, fixture.recoveryCodes.generations)
    }

    /** A user who has spent every code has nothing left to invalidate, so a new set is safe. */
    @Test
    fun `an exhausted code set is replaced on the next enrollment`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        fixture.enrollPasskey(ada)
        fixture.recoveryCodes.exhaust(ada.userId)

        val started = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))
        val confirmed = assertIs<FlowResult.Success<WebAuthnEnrollmentConfirmed>>(
            fixture.confirmEnrollment(ada, started.value.factorId),
        )

        assertNotNull(confirmed.value.recoveryCodes)
    }

    /**
     * The label is what tells two passkeys apart in the account UI, so a user who names one and
     * finds the adapter's default has been silently ignored.
     */
    @Test
    fun `the confirmed label replaces the adapter default`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val started = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))

        assertIs<FlowResult.Success<WebAuthnEnrollmentConfirmed>>(
            fixture.confirmEnrollment(ada, started.value.factorId, label = "Ada's phone"),
        )

        val factor = assertNotNull(fixture.mfaRepository.findFactor(started.value.factorId))
        assertEquals("Ada's phone", factor.label)
    }

    /** Nothing to apply is not an error; the authenticator's own name stands. */
    @Test
    fun `a blank label leaves the default in place`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val started = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))

        assertIs<FlowResult.Success<WebAuthnEnrollmentConfirmed>>(
            fixture.confirmEnrollment(ada, started.value.factorId, label = "   "),
        )

        assertEquals("Security key", assertNotNull(fixture.mfaRepository.findFactor(started.value.factorId)).label)
    }

    /**
     * Rejected before the factor is touched.
     *
     * The alternative — activate, then fail on the oversized write — would hand the user a
     * working passkey and an error telling them it did not work.
     */
    @Test
    fun `an over-long label is refused and the factor stays pending`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val started = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))

        val failure = assertIs<FlowResult.Failure>(
            fixture.confirmEnrollment(ada, started.value.factorId, label = "y".repeat(65)),
        )
        assertEquals(AuthError.ValidationFailed(mapOf("label" to "too_long")), failure.error)

        val factor = assertNotNull(fixture.mfaRepository.findFactor(started.value.factorId))
        assertEquals(MfaFactorStatus.PENDING, factor.status)
    }

    @Test
    fun `confirming another user's factor is reported as not found`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val mallory = fixture.createUser("mallory")

        val adaStarted = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))

        val failure = assertIs<FlowResult.Failure>(
            fixture.confirmEnrollment(mallory, adaStarted.value.factorId),
        )
        // Not `Forbidden`: a distinguishable error would confirm the id exists.
        assertEquals(AuthError.NotFound, failure.error)

        val factor = assertNotNull(fixture.mfaRepository.findFactor(adaStarted.value.factorId))
        assertEquals(MfaFactorStatus.PENDING, factor.status)
    }

    @Test
    fun `a factor id that belongs to nobody is reported as not found`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")

        val failure = assertIs<FlowResult.Failure>(fixture.confirmEnrollment(ada, MfaFactorId.random()))
        assertEquals(AuthError.NotFound, failure.error)
    }

    /** A response the adapter refuses must leave the factor unusable, not half-enrolled. */
    @Test
    fun `a rejected authenticator response leaves the factor pending`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val started = assertIs<FlowResult.Success<WebAuthnEnrollmentStarted>>(fixture.beginEnrollment(ada))

        fixture.webauthn.rejectEnrollment = true
        val failure = assertIs<FlowResult.Failure>(fixture.confirmEnrollment(ada, started.value.factorId))

        assertEquals(AuthError.MfaInvalid, failure.error)
        val factor = assertNotNull(fixture.mfaRepository.findFactor(started.value.factorId))
        assertEquals(MfaFactorStatus.PENDING, factor.status)
        assertEquals(0, fixture.recoveryCodes.generations)
    }

    /**
     * Trusted devices are exemptions from *this* factor. Leaving them alive would mean a
     * re-enrolled passkey is never asked for on any machine trusted under the old one.
     */
    @Test
    fun `removing a passkey revokes every trusted device`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        fixture.trustADevice(ada)
        val factorId = fixture.enrollPasskey(ada)

        assertIs<FlowResult.Success<Unit>>(fixture.removeCredential(ada, factorId))

        val devices = fixture.devices.rows()
        assertTrue(devices.isNotEmpty())
        assertTrue(devices.all { it.revokedAt != null })
        assertEquals(
            setOf(TrustedDeviceRevocationReason.MFA_CHANGED),
            devices.mapNotNull { it.revokedReason }.toSet(),
        )
        assertEquals(MfaFactorStatus.REVOKED, assertNotNull(fixture.mfaRepository.findFactor(factorId)).status)
        assertContains(fixture.outbox.published, DomainEvent.MfaDisabled(ada.userId, MfaType.WEBAUTHN))
    }

    /**
     * Removing a factor is the most valuable action for someone holding a stolen session, so a
     * recent reauthentication is not enough on its own.
     */
    @Test
    fun `removing a passkey requires the current password`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        fixture.trustADevice(ada)
        val factorId = fixture.enrollPasskey(ada)

        val omitted = assertIs<FlowResult.Failure>(
            fixture.removeCredential(ada, factorId, currentPassword = null),
        )
        assertEquals(AuthError.InvalidCredentials, omitted.error)

        val wrong = assertIs<FlowResult.Failure>(
            fixture.removeCredential(ada, factorId, currentPassword = "not-the-password"),
        )
        assertEquals(AuthError.InvalidCredentials, wrong.error)

        assertEquals(MfaFactorStatus.ACTIVE, assertNotNull(fixture.mfaRepository.findFactor(factorId)).status)
        assertTrue(fixture.devices.rows().all { it.revokedAt == null })
    }

    /** Knowing your own password must not let you strip a factor off someone else's account. */
    @Test
    fun `removing another user's passkey is reported as not found`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val mallory = fixture.createUser("mallory")
        val factorId = fixture.enrollPasskey(ada)

        val failure = assertIs<FlowResult.Failure>(fixture.removeCredential(mallory, factorId))

        assertEquals(AuthError.NotFound, failure.error)
        assertEquals(MfaFactorStatus.ACTIVE, assertNotNull(fixture.mfaRepository.findFactor(factorId)).status)
    }

    /**
     * The limits are declared, not merely intended.
     *
     * Without this, deleting a `require(managementLimit(...))` line breaks nothing that fails.
     */
    @Test
    fun `every passkey management flow consumes a rate-limit permit`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val factorId = fixture.enrollPasskey(ada)
        fixture.removeCredential(ada, factorId)

        val dimensions = fixture.rateLimiter.dimensions().toSet()
        assertContains(dimensions, "mfa.webauthn.begin")
        assertContains(dimensions, "mfa.webauthn.confirm")
        assertContains(dimensions, "mfa.webauthn.remove")
        // Keyed per account, not per address: one stolen session must not hide behind a proxy
        // pool, and one abusive account must not throttle everyone sharing its egress.
        assertTrue(fixture.rateLimiter.consumed.all { it.value == ada.userId.value.toString() })
    }

    @Test
    fun `a limited caller is refused before the factor row is written`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        fixture.rateLimiter.denied = "mfa.webauthn.begin"

        val failure = assertIs<FlowResult.Failure>(fixture.beginEnrollment(ada))

        assertIs<AuthError.RateLimited>(failure.error)
        assertTrue(fixture.mfaRepository.rows().isEmpty())
    }

    /** Sanity check on the fixture: the password gate is the *second* control, not the only one. */
    @Test
    fun `a stale reauthentication blocks removal even with the right password`(): Unit = runTest {
        val fixture = MfaFixture()
        val ada = fixture.createUser("ada")
        val factorId = fixture.enrollPasskey(ada)

        val failure = assertIs<FlowResult.Failure>(
            fixture.removeCredential(ada, factorId, currentPassword = PASSWORD, now = DAY_1),
        )

        assertEquals(AuthError.ReauthenticationRequired, failure.error)
        assertEquals(MfaFactorStatus.ACTIVE, assertNotNull(fixture.mfaRepository.findFactor(factorId)).status)
    }
}
