package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.SessionRevocationReason
import dev.kamiql.helium.flow.ChallengeDescriptor
import dev.kamiql.helium.flow.FlowResult
import kotlinx.coroutines.test.runTest
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Step-up, which exists so that sensitive operations need proof of identity taken *recently* —
 * not proof taken whenever the session happened to start.
 *
 * The suite is written around two questions. The first is the bug it was built for: a step-up
 * must refresh the session in front of it and create nothing, because the UI used to satisfy the
 * prompt by replaying login and so filled the account's device list with sessions the user never
 * knowingly started. The second is the one that matters more: a step-up handle is a credential
 * for reaching password changes and factor removals, so what it is bound to, and what it is worth
 * elsewhere, are the things worth attacking.
 */
class ReauthenticationTest {

    private companion object {
        const val ALICE = "alice"
        const val BOB = "bob"

        /** Comfortably past `Lifetimes.reauthenticationWindow`. */
        val LATER = T0.plus(Duration.ofHours(1))
    }

    // =========================================================================
    // the session is refreshed, not replaced
    // =========================================================================

    @Test
    fun `a step-up refreshes the caller's session and issues no other`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE, mfaEnrolled = false)
        val session = fixture.signIn(ALICE)

        val result = fixture.reauthenticate(session, now = LATER)

        assertIs<FlowResult.Success<Unit>>(result)
        val rows = fixture.sessions.rows()
        assertEquals(1, rows.size, "a step-up must not add a session")
        assertEquals(session.id, rows.single().id)
        assertEquals(LATER, rows.single().authenticatedAt, "the step-up clock must have moved")
    }

    @Test
    fun `a step-up with the wrong password changes nothing`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE, mfaEnrolled = false)
        val session = fixture.signIn(ALICE)

        val result = fixture.reauthenticate(session, password = "wrong", now = LATER)

        val failure = assertIs<FlowResult.Failure>(result)
        assertEquals(AuthError.InvalidCredentials, failure.error)
        assertEquals(T0, fixture.sessions.rows().single().authenticatedAt)
    }

    /**
     * A step-up adds evidence and withdraws none.
     *
     * The merge matters because `amr` is what downstream services read to make their own step-up
     * decisions. A session that cleared a passkey challenge at sign-in and later confirms a
     * deletion with its password must not come out of that looking password-only — the ID tokens
     * minted from it would start claiming less than the session actually proved.
     */
    @Test
    fun `a step-up merges into the recorded amr rather than replacing it`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val session = fixture.signIn(ALICE)
        assertTrue(session.mfaSatisfied, "the sign-in itself should have cleared a factor")

        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(session, now = LATER))
        assertIs<FlowResult.Success<Unit>>(
            fixture.completeReauthentication(session, challenge.transactionId, now = LATER),
        )

        assertEquals(
            setOf(AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP),
            fixture.sessions.rows().single().authenticationMethods,
        )
    }

    /**
     * A session revoked while the user was typing stays revoked.
     *
     * The window is real: the prompt is open for as long as somebody takes to find their phone,
     * and "sign out every other device" is exactly what a person does when they suspect the
     * session on the other side of this prompt. A step-up that resurrected it would undo the one
     * control that was working.
     */
    @Test
    fun `a step-up cannot revive a session revoked while the prompt was open`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE, mfaEnrolled = false)
        val session = fixture.signIn(ALICE)
        fixture.sessions.revokeAllForUser(session.userId, T0, SessionRevocationReason.USER_REVOKED_DEVICE)

        val result = fixture.reauthenticate(session, now = LATER)

        val failure = assertIs<FlowResult.Failure>(result)
        assertEquals(AuthError.AuthenticationRequired, failure.error)
    }

    @Test
    fun `an anonymous caller is told to sign in rather than prompted for a password`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE, mfaEnrolled = false)

        val result = fixture.reauthenticateAnonymously()

        val failure = assertIs<FlowResult.Failure>(result)
        assertEquals(AuthError.AuthenticationRequired, failure.error)
        assertTrue(fixture.sessions.rows().isEmpty(), "and certainly no session was created")
    }

    // =========================================================================
    // the second factor
    // =========================================================================

    @Test
    fun `an account with a second factor must present it`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val session = fixture.signIn(ALICE)

        val result = fixture.reauthenticate(session, now = LATER)

        val challenge = assertIs<FlowResult.Challenge>(result)
        assertEquals(ChallengeDescriptor.MFA_REQUIRED, challenge.code)
        assertEquals(
            T0, fixture.sessions.rows().single().authenticatedAt,
            "the clock must not move until the factor is answered",
        )
    }

    /**
     * No trusted-device exemption here, unlike at sign-in.
     *
     * The exemption exists so a recognised machine can skip the challenge when signing in.
     * Extending it to step-up would mean the operations step-up guards — password change, factor
     * removal, account deletion — are reachable with a stolen session and a password, from
     * precisely the machine somebody holding both is most likely to be sitting at.
     */
    @Test
    fun `a trusted device does not buy a step-up out of its second factor`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        fixture.trustThisDevice(ALICE)
        val session = fixture.signIn(ALICE)

        assertIs<FlowResult.Challenge>(fixture.reauthenticate(session, now = LATER))
    }

    @Test
    fun `a wrong second factor leaves the clock where it was`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val session = fixture.signIn(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(session, now = LATER))

        val result = fixture.completeReauthentication(
            session = session,
            transactionId = challenge.transactionId,
            now = LATER,
            response = MfaResponse.Code(Secret.of("000000")),
        )

        assertIs<FlowResult.Failure>(result)
        assertEquals(T0, fixture.sessions.rows().single().authenticatedAt)
    }

    /** One guess per challenge: the handle is spent whether or not the answer was right. */
    @Test
    fun `a step-up handle cannot be answered twice`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val session = fixture.signIn(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(session, now = LATER))

        assertIs<FlowResult.Success<Unit>>(
            fixture.completeReauthentication(session, challenge.transactionId, now = LATER),
        )
        val replay = fixture.completeReauthentication(session, challenge.transactionId, now = LATER)

        assertEquals(AuthError.MfaExpired, assertIs<FlowResult.Failure>(replay).error)
    }

    // =========================================================================
    // what the handle is bound to
    // =========================================================================

    /**
     * Handle substitution across sessions.
     *
     * Two live sessions on one account is the ordinary state of a person with a laptop and a
     * phone — and also the state during a takeover. If a handle drawn in one refreshed the other,
     * an attacker holding a stolen cookie could wait for the owner to answer their own step-up
     * prompt and ride it into a password change.
     */
    @Test
    fun `a handle drawn in one session cannot refresh another`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val laptop = fixture.signIn(ALICE)
        val phone = fixture.signIn(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(laptop, now = LATER))

        val result = fixture.completeReauthentication(phone, challenge.transactionId, now = LATER)

        assertEquals(AuthError.MfaExpired, assertIs<FlowResult.Failure>(result).error)
        assertTrue(
            fixture.sessions.rows().all { it.authenticatedAt == T0 },
            "neither session may be refreshed by a handle that was not theirs",
        )
    }

    /** And not across accounts, for the same reason a login handle may not. */
    @Test
    fun `a handle drawn by one account cannot refresh another account's session`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        fixture.createUser(BOB)
        val alice = fixture.signIn(ALICE)
        val bob = fixture.signIn(BOB)
        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(alice, now = LATER))

        val result = fixture.completeReauthentication(bob, challenge.transactionId, now = LATER)

        assertEquals(AuthError.MfaExpired, assertIs<FlowResult.Failure>(result).error)
    }

    /**
     * A step-up handle is not a sign-in handle.
     *
     * This is what the separate transaction *kind* is for. Were the two interchangeable, a prompt
     * the user answered to confirm a deletion would mint a brand-new session for whoever
     * presented the answer — turning the endpoint this whole change was written to remove back
     * on, and worse, as a session-minting oracle.
     */
    @Test
    fun `a step-up handle cannot be spent at the login MFA endpoint`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val session = fixture.signIn(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(session, now = LATER))

        val result = fixture.completeMfa(challenge.transactionId, rememberDevice = false, now = LATER)

        assertEquals(AuthError.MfaExpired, assertIs<FlowResult.Failure>(result).error)
        assertEquals(1, fixture.sessions.rows().size, "no session may come out of a step-up handle")
    }

    /** And the reverse: a login handle must not refresh a session that already exists. */
    @Test
    fun `a login handle cannot be spent at the step-up endpoint`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val session = fixture.signIn(ALICE)
        val login = assertIs<FlowResult.Challenge>(fixture.login(ALICE, now = LATER))

        val result = fixture.completeReauthentication(session, login.transactionId, now = LATER)

        assertEquals(AuthError.MfaExpired, assertIs<FlowResult.Failure>(result).error)
    }

    /**
     * Drawing the nonce a passkey needs works for either kind of handle, and consumes neither.
     *
     * The endpoint is shared on purpose — the same account needs the same nonce whichever prompt
     * it is answering — and it hands out nothing that is worth anything without the answer that
     * follows. What the answer then buys is decided where the handle is *spent*, which the tests
     * above cover.
     */
    @Test
    fun `the challenge endpoint serves a step-up handle without consuming it`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        val alice = fixture.createUser(ALICE)
        fixture.seedPasskey(alice)
        val session = fixture.signIn(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(session, now = LATER))

        assertIs<FlowResult.Success<MfaChallengeStarted>>(
            fixture.beginMfaChallenge(challenge.transactionId, now = LATER),
        )

        assertIs<FlowResult.Success<Unit>>(
            fixture.completeReauthentication(session, challenge.transactionId, now = LATER),
        )
    }

    // =========================================================================
    // the audit trail
    // =========================================================================

    /**
     * Every sensitive operation is preceded by one of these, so the step-up is the row that says
     * who was at the keyboard. Counting it as a login instead would bury that in sign-in traffic.
     */
    @Test
    fun `a step-up is recorded as its own event`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE, mfaEnrolled = false)
        val session = fixture.signIn(ALICE)
        fixture.outbox.published.clear()

        fixture.reauthenticate(session, now = LATER)

        val event = fixture.outbox.rows().filterIsInstance<DomainEvent.Reauthenticated>().single()
        assertEquals(session.userId, event.userId)
        assertEquals(session.id, event.sessionId)
        assertTrue(
            fixture.outbox.rows().none { it is DomainEvent.LoginSucceeded },
            "a step-up is not a sign-in and must not be reported as one",
        )
    }

    @Test
    fun `a completed second factor is recorded as a step-up that used one`(): Unit = runTest {
        val fixture = TrustedDeviceFixture()
        fixture.createUser(ALICE)
        val session = fixture.signIn(ALICE)
        val challenge = assertIs<FlowResult.Challenge>(fixture.reauthenticate(session, now = LATER))
        fixture.outbox.published.clear()

        fixture.completeReauthentication(session, challenge.transactionId, now = LATER)

        val event = fixture.outbox.rows().filterIsInstance<DomainEvent.Reauthenticated>().single()
        assertTrue(event.mfa)
    }
}
