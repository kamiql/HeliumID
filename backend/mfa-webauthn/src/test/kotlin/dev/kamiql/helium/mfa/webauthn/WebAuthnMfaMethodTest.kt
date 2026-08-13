package dev.kamiql.helium.mfa.webauthn

import com.webauthn4j.data.AuthenticatorAttachment
import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.test.authenticator.webauthn.NoneAttestationAuthenticator
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor
import com.webauthn4j.test.client.ClientPlatform
import com.webauthn4j.util.Base64UrlUtil
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.WebAuthnRelyingParty
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.VerificationChallenge
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * End-to-end ceremony tests against webauthn4j's authenticator emulator.
 *
 * The emulator matters: a passkey test that hand-rolls its fixtures proves only that the fixture
 * builder and the verifier agree. Here every registration and every assertion is a real signature
 * over the real challenge this adapter issued, so a change that quietly stops checking one is a
 * failing test rather than a green one.
 */
class WebAuthnMfaMethodTest {

    private val rpId = "example.com"
    private val origin = "https://example.com"

    private val relyingParty = WebAuthnRelyingParty(id = rpId, name = "Helium", origins = setOf(origin))

    private val userId = UserId.random()
    private val now: Instant = Instant.parse("2026-08-13T10:15:30Z")

    private val transactions = FakeTransactionStore()
    private val mfaRepository = FakeMfaRepository()
    private val credentials = FakeWebAuthnCredentialRepository()

    private val users = mockk<UserRepository>().also {
        coEvery { it.findById(userId) } returns User(
            id = userId,
            username = Username.restore("ada", "ada"),
            primaryEmail = EmailAddress.restore("ada@example.com", "ada@example.com"),
            firstName = "Ada",
            lastName = "Lovelace",
            status = UserStatus.ACTIVE,
            emailVerifiedAt = now,
            createdAt = now,
            updatedAt = now,
            version = 1L,
        )
    }

    /** A fresh authenticator per test: credential store and signature counter must not leak. */
    private val authenticator = NoneAttestationAuthenticator()
    private val client = ClientPlatform(Origin.create(origin), WebAuthnAuthenticatorAdaptor(authenticator))

    private fun method(rp: WebAuthnRelyingParty = relyingParty) =
        WebAuthnMfaMethod(mfaRepository, credentials, users, transactions, TestRandomSource(), rp)

    // ---------------------------------------------------------------- happy path

    @Test
    fun `enrolls a passkey and then verifies an assertion from it`() = runTest {
        val subject = method()

        val factorId = enroll(subject)

        assertEquals(MfaType.WEBAUTHN, mfaRepository.findFactor(factorId)?.type)
        assertTrue(mfaRepository.findFactor(factorId)!!.isActive)
        assertTrue(subject.isEnrolled(userId))
        assertTrue(transactions.isEmpty(), "the registration challenge must be consumed, not left behind")

        val result = subject.verify(userId, assertFrom(subject), now)

        val verified = assertIs<MfaVerificationResult.Verified>(result)
        assertEquals(factorId, verified.factorId)
        // WebAuthn has no time step to burn; replay is stopped by the single-use challenge.
        assertNull(verified.acceptedStep)
    }

    @Test
    fun `stores the user handle as the opaque user id, never the email`() = runTest {
        val options = (method().beginEnrollment(userId, now) as EnrollmentChallenge.WebAuthn).options

        val handle = Base64UrlUtil.decode(options.userHandle)
        assertEquals(16, handle.size)
        assertFalse(options.userHandle.contains("ada"), "the user handle must not carry the username")
        assertEquals(userId.value.mostSignificantBits, java.nio.ByteBuffer.wrap(handle).long)
    }

    @Test
    fun `registration and authentication challenges use different transaction kinds`() = runTest {
        val subject = method()
        enroll(subject)
        subject.beginVerification(userId, now)

        assertEquals(
            2,
            transactions.kindsWritten.size,
            "a registration challenge answerable as a login assertion is a login without a login",
        )
    }

    // ---------------------------------------------------------------- wrong response shape

    @Test
    fun `confirmEnrollment refuses a typed code`() = runTest {
        val subject = method()
        val challenge = subject.beginEnrollment(userId, now) as EnrollmentChallenge.WebAuthn

        val accepted = subject.confirmEnrollment(
            challenge.factorId,
            MfaResponse.Code(Secret.of("123456")),
            now,
        )

        assertFalse(accepted)
        assertFalse(mfaRepository.findFactor(challenge.factorId)!!.isActive)
    }

    @Test
    fun `verify refuses a typed code and a registration response`() = runTest {
        val subject = method()
        enroll(subject)
        subject.beginVerification(userId, now)

        assertEquals(
            MfaVerificationResult.Rejected,
            subject.verify(userId, MfaResponse.Code(Secret.of("123456")), now),
        )
        assertEquals(
            MfaVerificationResult.Rejected,
            subject.verify(
                userId,
                MfaResponse.WebAuthnRegistration("aa", "bb", "cc", emptyList()),
                now,
            ),
        )
    }

    // ---------------------------------------------------------------- replay

    @Test
    fun `an assertion cannot be replayed against the same challenge`() = runTest {
        val subject = method()
        enroll(subject)
        val assertion = assertFrom(subject)

        assertIs<MfaVerificationResult.Verified>(subject.verify(userId, assertion, now))

        // The challenge is gone, so the second presentation cannot even be evaluated.
        assertEquals(MfaVerificationResult.Expired, subject.verify(userId, assertion, now))
    }

    @Test
    fun `a failed attempt still spends the challenge`() = runTest {
        val subject = method()
        enroll(subject)
        subject.beginVerification(userId, now)

        val garbage = MfaResponse.WebAuthnAssertion("aa", "bb", "cc", "dd", null)
        assertEquals(MfaVerificationResult.Rejected, subject.verify(userId, garbage, now))

        // Otherwise a challenge could be ground against until something sticks.
        assertEquals(MfaVerificationResult.Expired, subject.verify(userId, garbage, now))
    }

    @Test
    fun `verify without a challenge is expired, not rejected`() = runTest {
        val subject = method()
        enroll(subject)

        // No beginVerification: nothing was issued, so there is nothing to answer.
        val garbage = MfaResponse.WebAuthnAssertion("aa", "bb", "cc", "dd", null)
        assertEquals(MfaVerificationResult.Expired, subject.verify(userId, garbage, now))
    }

    // ---------------------------------------------------------------- phishing resistance

    @Test
    fun `an assertion produced at an origin outside the allowed set is rejected`() = runTest {
        val subject = method()
        enroll(subject)

        val options = (subject.beginVerification(userId, now) as VerificationChallenge.WebAuthn).options
        // The phishing case: same authenticator, same credential, same challenge — but the page
        // asking for it lives somewhere the relying party never authorized.
        client.origin = Origin.create("https://evil.example")
        val assertion = assertionResponse(options)

        assertEquals(MfaVerificationResult.Rejected, subject.verify(userId, assertion, now))
    }

    @Test
    fun `a credential registered under a different relying-party id is rejected`() = runTest {
        val subject = method()
        enroll(subject)
        val assertion = assertFrom(subject)

        // The deployment moved domain. The stored credential is scoped to the old one and must
        // fail loudly rather than be accepted against the new relying party.
        val moved = method(WebAuthnRelyingParty(id = "elsewhere.test", name = "Helium", origins = setOf(origin)))

        assertEquals(MfaVerificationResult.Rejected, moved.verify(userId, assertion, now))
    }

    // ---------------------------------------------------------------- counter policy

    @Test
    fun `a signature counter that fails to advance is rejected`() = runTest {
        val subject = method()
        val factorId = enroll(subject)
        val assertion = assertFrom(subject)

        // Rewind nothing; push the stored counter past anything this authenticator can report.
        // That is what a cloned authenticator looks like from the server's side.
        credentials.forceSignatureCounter(factorId, Long.MAX_VALUE / 2)

        assertEquals(MfaVerificationResult.Rejected, subject.verify(userId, assertion, now))
    }

    @Test
    fun `an authenticator that never keeps a counter still verifies`() = runTest {
        // Counting disabled: both the stored and the reported value stay zero, which WebAuthn L3
        // §7.2 step 22 says to skip rather than treat as a regression.
        authenticator.isCountUpEnabled = false

        val subject = method()
        val factorId = enroll(subject)
        assertEquals(0L, credentials.single().signatureCounter)

        val result = subject.verify(userId, assertFrom(subject), now)

        assertEquals(factorId, assertIs<MfaVerificationResult.Verified>(result).factorId)
    }

    // ---------------------------------------------------------------- factor lifecycle

    @Test
    fun `beginVerification returns null when the user has no active passkey`() = runTest {
        assertNull(method().beginVerification(userId, now))
    }

    @Test
    fun `beginVerification returns null once the only passkey is revoked`() = runTest {
        val subject = method()
        val factorId = enroll(subject)
        mfaRepository.revokeFactor(factorId, now)

        assertNull(subject.beginVerification(userId, now))
        assertFalse(subject.isEnrolled(userId))
    }

    @Test
    fun `a revoked passkey cannot be used even though its credential row survives`() = runTest {
        val subject = method()
        val factorId = enroll(subject)
        val assertion = assertFrom(subject)

        mfaRepository.revokeFactor(factorId, now)
        // The row is deliberately still there — that is what keeps re-registration excluded.
        assertNotNull(credentials.findByFactor(factorId))

        assertEquals(MfaVerificationResult.Rejected, subject.verify(userId, assertion, now))
    }

    @Test
    fun `enrollment excludes credentials whose factor was revoked`() = runTest {
        val subject = method()
        val factorId = enroll(subject)
        mfaRepository.revokeFactor(factorId, now)

        val options = (subject.beginEnrollment(userId, now) as EnrollmentChallenge.WebAuthn).options

        assertEquals(
            listOf(Base64UrlUtil.encodeToString(credentials.single().credentialId)),
            options.excludeCredentialIds,
            "a removed passkey must not be silently re-registrable",
        )
    }

    @Test
    fun `restarting enrollment revokes the abandoned pending factor`() = runTest {
        val subject = method()
        val first = subject.beginEnrollment(userId, now) as EnrollmentChallenge.WebAuthn
        val honest = registrationResponseFor(first)

        subject.beginEnrollment(userId, now)

        assertFalse(mfaRepository.findFactor(first.factorId)!!.isActive)
        // Even with a response the abandoned ceremony would have accepted, the factor is gone.
        assertFalse(subject.confirmEnrollment(first.factorId, honest, now))
    }

    @Test
    fun `confirmEnrollment rejects a credential id the attestation does not cover`() = runTest {
        val subject = method()
        val challenge = subject.beginEnrollment(userId, now) as EnrollmentChallenge.WebAuthn
        val honest = registrationResponseFor(challenge)

        val tampered = honest.copy(credentialId = Base64UrlUtil.encodeToString(ByteArray(32) { 7 }))

        assertFalse(subject.confirmEnrollment(challenge.factorId, tampered, now))
    }

    // ---------------------------------------------------------------- ceremony helpers

    /** Runs a full registration ceremony and returns the now-active factor id. */
    private suspend fun enroll(subject: WebAuthnMfaMethod): MfaFactorId {
        val challenge = subject.beginEnrollment(userId, now) as EnrollmentChallenge.WebAuthn
        val accepted = subject.confirmEnrollment(challenge.factorId, registrationResponseFor(challenge), now)
        assertTrue(accepted, "the emulator's registration must pass verification")
        return challenge.factorId
    }

    /**
     * Drives `navigator.credentials.create()` from the options the adapter produced.
     *
     * Building the client request out of the adapter's own output is the point: if the adapter
     * ever emits a challenge or an rp id it does not then verify against, this stops matching.
     */
    private fun registrationResponseFor(
        challenge: EnrollmentChallenge.WebAuthn,
    ): MfaResponse.WebAuthnRegistration {
        val options = challenge.options
        val credential = client.create(
            PublicKeyCredentialCreationOptions(
                PublicKeyCredentialRpEntity(options.rpId, options.rpName),
                PublicKeyCredentialUserEntity(
                    Base64UrlUtil.decode(options.userHandle),
                    options.userName,
                    options.userDisplayName,
                ),
                DefaultChallenge(Base64UrlUtil.decode(options.challenge)),
                options.algorithms.map {
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.create(it),
                    )
                },
                null,
                emptyList(),
                // The emulator dereferences authenticatorSelection unconditionally, so it has to be
                // present here even though a browser treats it as optional. The values mirror what a
                // second-factor security key would be asked for: non-discoverable, UV not demanded.
                AuthenticatorSelectionCriteria(
                    AuthenticatorAttachment.CROSS_PLATFORM,
                    ResidentKeyRequirement.DISCOURAGED,
                    UserVerificationRequirement.PREFERRED,
                ),
                null,
                null,
            ),
        )
        val response = credential.response!!
        return MfaResponse.WebAuthnRegistration(
            credentialId = Base64UrlUtil.encodeToString(credential.rawId),
            clientDataJson = Base64UrlUtil.encodeToString(response.clientDataJSON),
            attestationObject = Base64UrlUtil.encodeToString(response.attestationObject),
            transports = listOf("internal"),
        )
    }

    /** Issues a challenge through the adapter and answers it with the emulator. */
    private suspend fun assertFrom(subject: WebAuthnMfaMethod): MfaResponse.WebAuthnAssertion {
        val challenge = assertNotNull(subject.beginVerification(userId, now)) as VerificationChallenge.WebAuthn
        return assertionResponse(challenge.options)
    }

    private fun assertionResponse(
        options: dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions,
    ): MfaResponse.WebAuthnAssertion {
        val credential = client.get(
            PublicKeyCredentialRequestOptions(
                DefaultChallenge(Base64UrlUtil.decode(options.challenge)),
                options.timeout.toMillis(),
                options.rpId,
                options.allowCredentialIds.map {
                    PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        Base64UrlUtil.decode(it),
                        null,
                    )
                },
                UserVerificationRequirement.PREFERRED,
                null,
            ),
        )
        val response = credential.response!!
        return MfaResponse.WebAuthnAssertion(
            credentialId = Base64UrlUtil.encodeToString(credential.rawId),
            clientDataJson = Base64UrlUtil.encodeToString(response.clientDataJSON),
            authenticatorData = Base64UrlUtil.encodeToString(response.authenticatorData),
            signature = Base64UrlUtil.encodeToString(response.signature),
            userHandle = response.userHandle?.let { Base64UrlUtil.encodeToString(it) },
        )
    }
}
