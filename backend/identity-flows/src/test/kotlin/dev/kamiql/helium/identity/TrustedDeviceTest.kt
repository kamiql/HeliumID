package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import dev.kamiql.helium.flow.ChallengeDescriptor
import dev.kamiql.helium.flow.FlowResult
import kotlinx.coroutines.test.runTest
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Trusted devices trade assurance for convenience, so this suite is written around the ways that
 * trade can go wrong: a token honoured for the wrong account, a token honoured for an account
 * that may never be exempt, a copied cookie, and a session that claims a second factor it never
 * saw.
 */
class TrustedDeviceTest {

    private companion object {
        const val ALICE = "alice"
        const val BOB = "bob"
        const val ADMIN = "admin"
    }

    // =========================================================================
    // honouring a token
    // =========================================================================

    @Test
    fun `a valid trusted device token skips the MFA challenge`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val cookie = fixture.trustThisDevice(ALICE)

        val result = fixture.login(ALICE, trustedDeviceToken = cookie, now = DAY_1)

        assertIs<FlowResult.Success<LoginSucceeded>>(result)
    }

    @Test
    fun `a login without a trusted device cookie is challenged`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)

        val result = fixture.login(ALICE)

        val challenge = assertIs<FlowResult.Challenge>(result)
        assertEquals(ChallengeDescriptor.MFA_REQUIRED, challenge.code)
    }

    @Test
    fun `an expired trusted device token is challenged`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val cookie = fixture.trustThisDevice(ALICE)

        val result = fixture.login(ALICE, trustedDeviceToken = cookie, now = AFTER_TRUST_EXPIRY)

        assertIs<FlowResult.Challenge>(result)
        // The expiry is absolute: presenting the token past it must not renew it either.
        assertEquals(0, fixture.devices.rotations)
    }

    @Test
    fun `a revoked trusted device token is challenged`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val alice = fixture.createUser(ALICE)
        val cookie = fixture.trustThisDevice(ALICE)
        fixture.trustedDevices.revoke(
            userId = alice,
            id = fixture.devices.rows().single().id,
            now = DAY_1,
            reason = TrustedDeviceRevocationReason.USER_REVOKED,
        )

        val result = fixture.login(ALICE, trustedDeviceToken = cookie, now = DAY_2)

        assertIs<FlowResult.Challenge>(result)
    }

    @Test
    fun `an unrecognised trusted device token is challenged`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        fixture.trustThisDevice(ALICE)

        val result = fixture.login(ALICE, trustedDeviceToken = "not-a-token-we-ever-issued", now = DAY_1)

        assertIs<FlowResult.Challenge>(result)
    }

    /**
     * Token substitution. A device exemption is a bearer credential, and a bearer credential that
     * is not bound to a subject lets anyone holding one impersonate the strongest account it
     * fits.
     */
    @Test
    fun `a trusted device token minted for one user never skips MFA for another`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val alice = fixture.createUser(ALICE)
        fixture.createUser(BOB)
        val aliceCookie = fixture.trustThisDevice(ALICE)

        val result = fixture.login(BOB, trustedDeviceToken = aliceCookie, now = DAY_1)

        assertIs<FlowResult.Challenge>(result)
        // Nor may Bob's attempt disturb Alice's device: her token is neither rotated nor, by
        // being mistaken for a replay, revoked.
        val aliceDevice = fixture.devices.rows().single()
        assertEquals(alice, aliceDevice.userId)
        assertTrue(aliceDevice.isActive(DAY_1))
        assertEquals(0, fixture.devices.rotations)
    }

    /**
     * An administrator's laptop is the single most valuable thing an attacker can be sitting in
     * front of, so the exemption is not merely refused for them — it is never evaluated, which
     * means nothing about their login depends on a value that could have been copied off the
     * machine.
     */
    @Test
    fun `a privileged user is challenged despite a valid token and the token is not rotated`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val admin = fixture.createUser(ADMIN, privileged = true)
        val cookie = fixture.mintDeviceOutsideTheFlow(admin)

        val result = fixture.login(ADMIN, trustedDeviceToken = cookie, now = DAY_1)

        assertIs<FlowResult.Challenge>(result)
        assertEquals(0, fixture.devices.lookups, "a privileged login must not consult the device table")
        assertEquals(0, fixture.devices.rotations)
    }

    /**
     * The `amr` of the resulting session is what every downstream step-up decision reads. A
     * trusted device skips the *prompt*; recording it as though the factor had been presented
     * would silently exempt the session from every later reauthentication too.
     */
    @Test
    fun `a session issued through the trusted device skip records only the password factor`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val cookie = fixture.trustThisDevice(ALICE)

        val result = fixture.login(ALICE, trustedDeviceToken = cookie, now = DAY_1)

        val success = assertIs<FlowResult.Success<LoginSucceeded>>(result)
        val session = success.value.session.session
        assertEquals(setOf(AuthenticationMethod.PASSWORD), session.authenticationMethods)
        assertFalse(session.mfaSatisfied, "a skipped challenge is not a satisfied one")
    }

    // =========================================================================
    // minting a token
    // =========================================================================

    @Test
    fun `a password login never mints a trusted device`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE, mfaEnrolled = false)
        fixture.createUser(BOB)

        val withoutMfa = fixture.login(ALICE)
        val withMfa = fixture.login(BOB)

        val success = assertIs<FlowResult.Success<LoginSucceeded>>(withoutMfa)
        assertEquals(TrustedDeviceDirective.Keep, success.value.trustedDevice)
        assertIs<FlowResult.Challenge>(withMfa)
        // A device minted on the strength of a password alone would make the first sign-in on a
        // new machine its own bypass.
        assertTrue(fixture.devices.rows().isEmpty())
    }

    @Test
    fun `completing MFA without remember device mints nothing`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.login(ALICE))

        val result = fixture.completeMfa(challenge.transactionId, rememberDevice = false)

        val success = assertIs<FlowResult.Success<LoginSucceeded>>(result)
        // Clear rather than Keep: reaching a challenge at all proves whatever device cookie this
        // browser holds did not satisfy it, so the value is dead and worth binning.
        assertEquals(TrustedDeviceDirective.Clear, success.value.trustedDevice)
        assertTrue(fixture.devices.rows().isEmpty())
    }

    @Test
    fun `completing MFA with remember device mints exactly one device`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val alice = fixture.createUser(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.login(ALICE))

        val result = fixture.completeMfa(challenge.transactionId, rememberDevice = true)

        val success = assertIs<FlowResult.Success<LoginSucceeded>>(result)
        val issued = assertIs<TrustedDeviceDirective.Issue>(success.value.trustedDevice)
        val stored = fixture.devices.rows().single()
        assertEquals(alice, stored.userId)
        assertEquals(stored.id, issued.device.device.id)
        assertEquals(T0.plus(Duration.ofDays(30)), stored.expiresAt)
        assertTrue(
            fixture.outbox.published.any { it is DomainEvent.TrustedDeviceAdded },
            "the account owner has to be told a device was trusted",
        )
    }

    /**
     * Ignored rather than rejected: failing the login would turn a checkbox into a sign-in error
     * for exactly the accounts that must keep working.
     */
    @Test
    fun `remember device is ignored but not rejected for a privileged user`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ADMIN, privileged = true)
        val challenge = assertIs<FlowResult.Challenge>(fixture.login(ADMIN))

        val result = fixture.completeMfa(challenge.transactionId, rememberDevice = true)

        val success = assertIs<FlowResult.Success<LoginSucceeded>>(result)
        assertEquals(TrustedDeviceDirective.Clear, success.value.trustedDevice)
        assertTrue(fixture.devices.rows().isEmpty())
    }

    // =========================================================================
    // rotation and reuse
    // =========================================================================

    @Test
    fun `a successful trusted device login rotates the token`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val original = fixture.trustThisDevice(ALICE)

        val first = assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.login(ALICE, trustedDeviceToken = original, now = DAY_1),
        )
        val successor = assertIs<TrustedDeviceDirective.Issue>(first.value.trustedDevice)
            .device.cookieValue()
        assertNotEquals(original, successor)

        // The successor is exercised first: presenting the superseded value revokes the device,
        // so the two assertions cannot be made in the other order.
        assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.login(ALICE, trustedDeviceToken = successor, now = DAY_2),
        )
        assertIs<FlowResult.Challenge>(
            fixture.login(ALICE, trustedDeviceToken = original, now = DAY_3),
        )
    }

    @Test
    fun `presenting a superseded token revokes the device and still demands MFA`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val original = fixture.trustThisDevice(ALICE)
        assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.login(ALICE, trustedDeviceToken = original, now = DAY_1),
        )

        val result = fixture.login(ALICE, trustedDeviceToken = original, now = DAY_2)

        assertIs<FlowResult.Challenge>(result)
        val device = fixture.devices.rows().single()
        assertEquals(TrustedDeviceRevocationReason.REUSE_DETECTED, device.revokedReason)
        assertFalse(device.isActive(DAY_2))
    }

    /**
     * The response to a detected theft must not be undone by the request that detected it.
     *
     * Reuse makes the login demand a second factor, and a challenge unwinds the enclosing
     * transaction by design — so the revocation and its notification only survive if they were
     * written through `requiresNew`. The fixture's transaction manager really does discard
     * everything else the unwound transaction wrote, which is what makes this an assertion
     * rather than a hope.
     */
    @Test
    fun `the reuse revocation and its event survive the rolled back login`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val original = fixture.trustThisDevice(ALICE)
        assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.login(ALICE, trustedDeviceToken = original, now = DAY_1),
        )

        val rollbacksBefore = fixture.transactions.rolledBack
        val independentBefore = fixture.transactions.independentCommits
        val eventsBefore = fixture.outbox.published.size

        assertIs<FlowResult.Challenge>(fixture.login(ALICE, trustedDeviceToken = original, now = DAY_2))

        assertEquals(rollbacksBefore + 1, fixture.transactions.rolledBack)
        assertEquals(independentBefore + 1, fixture.transactions.independentCommits)
        assertEquals(
            TrustedDeviceRevocationReason.REUSE_DETECTED,
            fixture.devices.rows().single().revokedReason,
        )
        val newEvents = fixture.outbox.published.drop(eventsBefore)
        assertIs<DomainEvent.TrustedDeviceReuseDetected>(newEvents.single())
    }

    /**
     * One alert per theft, not one per attempt.
     *
     * Whoever holds the copied cookie can re-send it as often as they like, and every replay
     * reaches the detector. If each one published, the volume of the account owner's security
     * mail would be a dial the attacker controls — and an inbox full of the same warning is how
     * people learn to ignore warnings.
     */
    @Test
    fun `replaying the same superseded token reports the theft only once`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val original = fixture.trustThisDevice(ALICE)
        assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.login(ALICE, trustedDeviceToken = original, now = DAY_1),
        )

        val eventsBefore = fixture.outbox.published.size
        repeat(4) {
            assertIs<FlowResult.Challenge>(fixture.login(ALICE, trustedDeviceToken = original, now = DAY_2))
        }

        val reuseEvents = fixture.outbox.published.drop(eventsBefore)
            .filterIsInstance<DomainEvent.TrustedDeviceReuseDetected>()
        assertEquals(1, reuseEvents.size)
    }

    /**
     * A cookie copied before an unrelated revocation is still worth catching afterwards.
     *
     * Were the superseded generation discarded on every revocation, detection would depend on
     * whether the owner happened to change their password before the thief got round to using
     * what they took.
     */
    @Test
    fun `a replay is still detected after the device was revoked for another reason`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val alice = fixture.createUser(ALICE)
        val original = fixture.trustThisDevice(ALICE)
        assertIs<FlowResult.Success<LoginSucceeded>>(
            fixture.login(ALICE, trustedDeviceToken = original, now = DAY_1),
        )

        fixture.devices.revokeAllForUser(alice, DAY_2, TrustedDeviceRevocationReason.PASSWORD_CHANGED)
        val eventsBefore = fixture.outbox.published.size

        assertIs<FlowResult.Challenge>(fixture.login(ALICE, trustedDeviceToken = original, now = DAY_3))

        val reuseEvents = fixture.outbox.published.drop(eventsBefore)
            .filterIsInstance<DomainEvent.TrustedDeviceReuseDetected>()
        assertEquals(1, reuseEvents.size)
        // The earlier revocation keeps its own reason: the reuse is a second fact about the
        // device, not a correction of why it was revoked.
        assertEquals(
            TrustedDeviceRevocationReason.PASSWORD_CHANGED,
            fixture.devices.rows().single().revokedReason,
        )
    }

    // =========================================================================
    // configuration
    // =========================================================================

    @Test
    fun `a zero trusted device lifetime mints nothing`(): Unit = runTest {
        val fixture = TrustedDeviceFixture(Lifetimes.DEFAULT.copy(trustedDevice = Duration.ZERO))
        fixture.createUser(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.login(ALICE))

        val result = fixture.completeMfa(challenge.transactionId, rememberDevice = true)

        val success = assertIs<FlowResult.Success<LoginSucceeded>>(result)
        assertEquals(TrustedDeviceDirective.Clear, success.value.trustedDevice)
        assertTrue(fixture.devices.rows().isEmpty())
    }

    @Test
    fun `a zero trusted device lifetime honours no existing token`(): Unit = runTest {
        val fixture = TrustedDeviceFixture(Lifetimes.DEFAULT.copy(trustedDevice = Duration.ZERO))
        val alice = fixture.createUser(ALICE)
        // Seeded directly: rows left over from before the feature was switched off, or written by
        // a deployment that had it on, must stop being honoured the moment it is off.
        fixture.seedDevice(alice, plaintext = "left-over-token")

        val result = fixture.login(ALICE, trustedDeviceToken = "left-over-token", now = DAY_1)

        assertIs<FlowResult.Challenge>(result)
        assertEquals(0, fixture.devices.lookups, "the kill switch must short-circuit before the lookup")
        assertTrue(fixture.devices.rows().single().isActive(DAY_1))
    }
}
