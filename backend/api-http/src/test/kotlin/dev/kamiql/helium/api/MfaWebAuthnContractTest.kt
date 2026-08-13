package dev.kamiql.helium.api

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.UserVerificationRequirement
import dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions
import dev.kamiql.helium.domain.mfa.WebAuthnRegistrationOptions
import dev.kamiql.helium.identity.MfaChallengeStarted
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.Json
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The passkey wire contract, which browser and mobile clients are written against.
 *
 * Field names and the shape rules on `/mfa/verify` are public API: a renamed key or a relaxed
 * check breaks every client silently, so both are asserted here rather than left to review.
 */
class MfaWebAuthnContractTest {

    /** The same configuration `installHeliumPlugins` gives ContentNegotiation. */
    private val json = Json {
        explicitNulls = false
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val assertion = WebAuthnAssertionRequest(
        credentialId = "Y3JlZGVudGlhbA",
        clientDataJson = "Y2xpZW50RGF0YQ",
        authenticatorData = "YXV0aERhdGE",
        signature = "c2lnbmF0dXJl",
        userHandle = null,
    )

    private fun verifyRequest(
        method: String,
        code: String? = null,
        webauthn: WebAuthnAssertionRequest? = null,
    ) = MfaVerifyRequest(
        transactionId = "mfa_tx_01J",
        method = method,
        code = code,
        webauthn = webauthn,
    )

    // --- /v1/auth/mfa/verify: exactly one answer, matching the declared method ---------

    @Test
    fun `a body carrying both a code and an assertion is rejected`() {
        // Ambiguous whichever method it claims: the server must not get to pick which credential
        // it verifies, or a caller can attach a throwaway second answer to probe the first.
        MfaType.entries.forEach { method ->
            assertEquals(
                MfaResponseResult.Invalid("ambiguous"),
                verifyRequest(method.token, code = "123456", webauthn = assertion).readResponse(method),
                "both fields accepted for ${method.token}",
            )
        }
    }

    @Test
    fun `webauthn answered with a typed code is rejected`() {
        val read = verifyRequest("webauthn", code = "123456").readResponse(MfaType.WEBAUTHN)

        assertEquals(MfaResponseResult.Invalid("method_mismatch"), read)
    }

    @Test
    fun `totp answered with an assertion is rejected`() {
        val read = verifyRequest("totp", webauthn = assertion).readResponse(MfaType.TOTP)

        assertEquals(MfaResponseResult.Invalid("method_mismatch"), read)
    }

    @Test
    fun `a body with no answer at all is rejected`() {
        assertEquals(
            MfaResponseResult.Invalid("missing"),
            verifyRequest("totp").readResponse(MfaType.TOTP),
        )
        assertEquals(
            MfaResponseResult.Invalid("missing"),
            verifyRequest("webauthn").readResponse(MfaType.WEBAUTHN),
        )
    }

    @Test
    fun `a blank code counts as absent rather than as a competing answer`() {
        // A form that ships `code: ""` for an untouched input must not turn a valid passkey
        // request into an ambiguous one.
        val read = verifyRequest("webauthn", code = "  ", webauthn = assertion).readResponse(MfaType.WEBAUTHN)

        assertIs<MfaResponseResult.Valid>(read)
        assertIs<MfaResponse.WebAuthnAssertion>(read.response)
    }

    @Test
    fun `a well-formed answer reaches the flow as the matching response`() {
        val typed = verifyRequest("totp", code = "123456").readResponse(MfaType.TOTP)
        assertEquals(MfaResponseResult.Valid(MfaResponse.Code(Secret.of("123456"))), typed)

        val recovery = verifyRequest("recovery_code", code = "aaaa-bbbb").readResponse(MfaType.RECOVERY_CODE)
        assertEquals(MfaResponseResult.Valid(MfaResponse.Code(Secret.of("aaaa-bbbb"))), recovery)

        val signed = verifyRequest("webauthn", webauthn = assertion).readResponse(MfaType.WEBAUTHN)
        assertEquals(MfaResponseResult.Valid(assertion.toDomain()), signed)
    }

    @Test
    fun `a malformed body is a validation problem and never a failed authentication`() {
        // Spending one of the transaction's five attempts on a client bug would let a caller
        // burn a legitimate user's challenge without ever guessing a secret.
        val status = ProblemMapper.statusFor(AuthError.ValidationFailed(mapOf("response" to "ambiguous")))

        assertFalse(status == HttpStatusCode.Unauthorized)
        assertEquals("validation_failed", AuthError.ValidationFailed(emptyMap()).code)
    }

    @Test
    fun `a pre-passkey client body still decodes unchanged`() {
        val body = """{"transaction_id":"mfa_tx_01J","method":"totp","code":"123456"}"""

        val decoded = json.decodeFromString(MfaVerifyRequest.serializer(), body)

        assertEquals("123456", decoded.code)
        assertNull(decoded.webauthn)
        assertFalse(decoded.rememberDevice)
    }

    @Test
    fun `the method token round-trips through the parser the server advertises`() {
        MfaType.entries.forEach { assertEquals(it, parseMfaType(it.token)) }
        assertEquals(MfaType.TOTP, parseMfaType("TOTP"))
        assertNull(parseMfaType("sms"))
    }

    // --- /v1/auth/mfa/challenge ------------------------------------------------------

    @Test
    fun `a totp challenge carries no webauthn options`() {
        val response = MfaChallengeStarted(method = MfaType.TOTP, webauthnOptions = null).toResponse()

        assertEquals("totp", response.method)
        assertNull(response.webauthn)
        // `explicitNulls = false` means absent, not `null`, on the wire. Clients must treat the
        // key as optional rather than expecting an explicit null.
        assertFalse(json.encodeToString(MfaChallengeResponse.serializer(), response).contains("webauthn"))
    }

    @Test
    fun `a webauthn challenge is rendered as request options the browser can use directly`() {
        val started = MfaChallengeStarted(
            method = MfaType.WEBAUTHN,
            webauthnOptions = WebAuthnAuthenticationOptions(
                challenge = "Y2hhbGxlbmdl",
                rpId = "helium.id",
                allowCredentialIds = listOf("Y3JlZA"),
                userVerification = UserVerificationRequirement.PREFERRED,
                timeout = Duration.ofSeconds(90),
            ),
        )

        val encoded = json.encodeToString(MfaChallengeResponse.serializer(), started.toResponse())

        assertTrue(encoded.contains(""""method":"webauthn""""))
        assertTrue(encoded.contains(""""rp_id":"helium.id""""))
        assertTrue(encoded.contains(""""allow_credential_ids":["Y3JlZA"]"""))
        // Lowercase enum name and milliseconds, both as the WebAuthn API expects them.
        assertTrue(encoded.contains(""""user_verification":"preferred""""))
        assertTrue(encoded.contains(""""timeout_ms":90000"""))
    }

    // --- /v1/me/mfa/webauthn ---------------------------------------------------------

    @Test
    fun `creation options are rendered as the browser expects them`() {
        val options = WebAuthnRegistrationOptions(
            challenge = "Y2hhbGxlbmdl",
            rpId = "helium.id",
            rpName = "HeliumID",
            userHandle = "dXNlcg",
            userName = "ada",
            userDisplayName = "Ada Lovelace",
            algorithms = WebAuthnRegistrationOptions.DEFAULT_ALGORITHMS,
            excludeCredentialIds = listOf("Y3JlZA"),
            userVerification = UserVerificationRequirement.REQUIRED,
            timeout = Duration.ofSeconds(120),
        )

        val encoded = json.encodeToString(WebAuthnRegistrationOptionsResponse.serializer(), options.toResponse())

        assertTrue(encoded.contains(""""rp_id":"helium.id""""))
        assertTrue(encoded.contains(""""rp_name":"HeliumID""""))
        assertTrue(encoded.contains(""""user_handle":"dXNlcg""""))
        assertTrue(encoded.contains(""""user_name":"ada""""))
        assertTrue(encoded.contains(""""user_display_name":"Ada Lovelace""""))
        assertTrue(encoded.contains(""""algorithms":[-7,-8,-257]"""))
        assertTrue(encoded.contains(""""exclude_credential_ids":["Y3JlZA"]"""))
        assertTrue(encoded.contains(""""user_verification":"required""""))
        assertTrue(encoded.contains(""""timeout_ms":120000"""))
    }

    @Test
    fun `a confirmation body decodes with the label and transports optional`() {
        val body = """
            {"factor_id":"3f1b0b6c-1f3f-4d3a-8a1e-5b2f7b6c9d01",
             "credential_id":"Y3JlZA","client_data_json":"Y2xpZW50",
             "attestation_object":"YXR0ZXN0"}
        """.trimIndent()

        val decoded = json.decodeFromString(WebAuthnConfirmRequest.serializer(), body)

        assertNull(decoded.label)
        assertEquals(emptyList(), decoded.transports)
        assertEquals(decoded.toDomain().credentialId, "Y3JlZA")
    }

    @Test
    fun `a confirmation without recovery codes omits them rather than sending an empty list`() {
        // An empty array would read as "your codes were regenerated and there are none", which
        // is exactly the opposite of "your existing codes are untouched".
        val encoded = json.encodeToString(
            WebAuthnConfirmResponse.serializer(),
            WebAuthnConfirmResponse(factorId = "3f1b0b6c-1f3f-4d3a-8a1e-5b2f7b6c9d01", recoveryCodes = null),
        )

        assertFalse(encoded.contains("recovery_codes"))
    }
}
