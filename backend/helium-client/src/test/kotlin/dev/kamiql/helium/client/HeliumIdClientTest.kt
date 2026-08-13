package dev.kamiql.helium.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Error mapping and request shaping, which is where a typed client earns its keep. */
class HeliumIdClientTest {

    private fun clientReturning(
        status: HttpStatusCode,
        body: String,
        contentType: String = "application/problem+json",
        headers: Map<String, String> = emptyMap(),
        record: ((io.ktor.client.request.HttpRequestData) -> Unit)? = null,
    ): HeliumIdClient {
        val engine = MockEngine { request ->
            record?.invoke(request)
            respond(
                content = ByteReadChannel(body),
                status = status,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf(contentType),
                    *headers.map { it.key to listOf(it.value) }.toTypedArray(),
                ),
            )
        }
        return HeliumIdClient("https://id.example", HttpClient(engine))
    }

    @Test
    fun `mfa_required becomes a typed MfaRequired carrying the transaction`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.Unauthorized,
            """
            {"type":"https://helium.id/errors/mfa-required","title":"Additional authentication required",
             "status":401,"code":"mfa_required","detail":"Complete the additional authentication step.",
             "transaction_id":"txn-123","methods":["totp","recovery_code"],
             "expires_at":"2026-08-12T10:00:00Z"}
            """.trimIndent(),
        )

        val failure = assertFailsWith<HeliumApiException> { client.login("ada", "pw") }
        val error = assertIs<HeliumError.MfaRequired>(failure.error)
        assertEquals("txn-123", error.transactionId)
        assertEquals(listOf("totp", "recovery_code"), error.methods)
        assertTrue(error.expiresAt != null)
    }

    @Test
    fun `rate_limited picks up retry_after from the body`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.TooManyRequests,
            """{"type":"t","title":"x","status":429,"code":"rate_limited","detail":"d","retry_after":42}""",
        )
        val failure = assertFailsWith<HeliumApiException> { client.me() }
        assertEquals(42.seconds, assertIs<HeliumError.RateLimited>(failure.error).retryAfter)
    }

    @Test
    fun `rate_limited falls back to the Retry-After header`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.TooManyRequests,
            """{"type":"t","title":"x","status":429,"code":"rate_limited","detail":"d"}""",
            headers = mapOf(HttpHeaders.RetryAfter to "7"),
        )
        val failure = assertFailsWith<HeliumApiException> { client.me() }
        assertEquals(7.seconds, assertIs<HeliumError.RateLimited>(failure.error).retryAfter)
    }

    @Test
    fun `validation_failed exposes the field reasons`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.UnprocessableEntity,
            """{"type":"t","title":"x","status":422,"code":"validation_failed","detail":"d",
                "errors":{"password":"too_short"}}""",
        )
        val failure = assertFailsWith<HeliumApiException> { client.me() }
        assertEquals(mapOf("password" to "too_short"), assertIs<HeliumError.ValidationFailed>(failure.error).fields)
    }

    @Test
    fun `an unknown code survives as Unexpected with the code intact`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.BadRequest,
            """{"type":"t","title":"x","status":400,"code":"brand_new_code","detail":"d"}""",
        )
        val failure = assertFailsWith<HeliumApiException> { client.me() }
        val error = assertIs<HeliumError.Unexpected>(failure.error)
        assertEquals("brand_new_code", error.code)
        assertEquals(400, error.status)
    }

    @Test
    fun `the token endpoint's RFC 6749 error shape is mapped too`(): Unit = runBlocking {
        val client = clientReturning(
            HttpStatusCode.BadRequest,
            """{"error":"invalid_grant","error_description":"expired"}""",
            contentType = "application/json",
        )
        val failure = assertFailsWith<HeliumApiException> {
            client.refresh("stale-token", "orders-web")
        }
        assertIs<HeliumError.InvalidGrant>(failure.error)
    }

    @Test
    fun `a non-JSON gateway error still produces a typed failure`(): Unit = runBlocking {
        val engine = MockEngine { respondError(HttpStatusCode.BadGateway, "<html>nope</html>") }
        val client = HeliumIdClient("https://id.example", HttpClient(engine))
        val failure = assertFailsWith<HeliumApiException> { client.me() }
        val error = assertIs<HeliumError.Unexpected>(failure.error)
        assertEquals(502, error.status)
        // The upstream body is never echoed back: it came from something in the middle.
        assertTrue(!error.detail.contains("nope"))
    }

    @Test
    fun `a confidential client authenticates with client_secret_basic`(): Unit = runBlocking {
        var seen: io.ktor.client.request.HttpRequestData? = null
        val client = clientReturning(
            HttpStatusCode.OK,
            """{"access_token":"a","token_type":"Bearer","expires_in":300,"scope":"openid"}""",
            contentType = "application/json",
            record = { seen = it },
        )
        client.clientCredentials("orders-api", "s3cr3t", setOf("orders:read"))

        val request = seen!!
        assertEquals(HttpMethod.Post, request.method)
        assertTrue(request.headers[HttpHeaders.Authorization]!!.startsWith("Basic "))
        assertEquals("https://id.example/oauth2/token", request.url.toString())
    }

    @Test
    fun `a public client sends client_id in the body and no Authorization header`(): Unit = runBlocking {
        var seen: io.ktor.client.request.HttpRequestData? = null
        val client = clientReturning(
            HttpStatusCode.OK,
            """{"access_token":"a","token_type":"Bearer","expires_in":300,"scope":"openid"}""",
            contentType = "application/json",
            record = { seen = it },
        )
        client.exchangeAuthorizationCode(
            code = "c",
            redirectUri = "https://app.example/cb",
            clientId = "spa",
            codeVerifier = Pkce.generateVerifier(),
        )
        assertEquals(null, seen!!.headers[HttpHeaders.Authorization])
    }

    @Test
    fun `bearer tokens are attached and CSRF is only sent on state changes`(): Unit = runBlocking {
        val seen = mutableListOf<io.ktor.client.request.HttpRequestData>()
        val engine = MockEngine { request ->
            seen += request
            respond(
                ByteReadChannel(if (request.method == HttpMethod.Get) "[]" else """{"codes":[]}"""),
                HttpStatusCode.OK,
                headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
            )
        }
        val client = HeliumIdClient.create("https://id.example") {
            httpClient = HttpClient(engine)
            bearerToken { "token-value" }
            csrfToken { "csrf-value" }
        }

        client.mfaFactors()
        client.regenerateRecoveryCodes()

        assertEquals("Bearer token-value", seen[0].headers[HttpHeaders.Authorization])
        assertEquals(null, seen[0].headers[CSRF_HEADER])
        assertEquals("csrf-value", seen[1].headers[CSRF_HEADER])
    }

    @Test
    fun `an unreachable server is a transport failure, not an API failure`(): Unit = runBlocking {
        val engine = MockEngine { throw java.io.IOException("connection refused") }
        val client = HeliumIdClient("https://id.example", HttpClient(engine))
        val failure = assertFailsWith<HeliumTransportException> { client.me() }
        assertTrue(!failure.message!!.contains("token"))
    }

    @Test
    fun `the authorization URL always requests code with S256`() {
        val client = HeliumIdClient("https://id.example/", HttpClient(MockEngine { respond("") }))
        val url = client.authorizationUrl(
            clientId = "spa",
            redirectUri = "https://app.example/cb?x=1",
            scope = setOf("openid", "orders:read"),
            state = "st",
            codeChallenge = "ch",
            nonce = "n",
        )
        assertTrue(url.startsWith("https://id.example/oauth2/authorize?"))
        assertTrue(url.contains("response_type=code"))
        assertTrue(url.contains("code_challenge_method=S256"))
        // The redirect URI must be encoded, or its own query string joins ours.
        assertTrue(url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fx%3D1"))
    }
}

/** The one piece of cryptography the SDK owns, so it gets its own checks. */
class PkceTest {

    @Test
    fun `a generated verifier matches RFC 7636's shape`() {
        repeat(50) {
            val verifier = Pkce.generateVerifier()
            assertTrue(verifier.length in 43..128, "length was ${verifier.length}")
            assertTrue(verifier.all { it.isLetterOrDigit() || it in "-._~" })
        }
    }

    @Test
    fun `verifiers are not repeated`() {
        val generated = List(200) { Pkce.generateVerifier() }
        assertEquals(200, generated.toSet().size)
    }

    @Test
    fun `the challenge is the unpadded base64url SHA-256 of the verifier`() {
        // RFC 7636 Appendix B's test vector.
        val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.challengeFor(verifier))
    }

    @Test
    fun `a malformed verifier is rejected before it reaches the token endpoint`() {
        assertFailsWith<IllegalArgumentException> { Pkce.challengeFor("too-short") }
        assertFailsWith<IllegalArgumentException> { Pkce.challengeFor("a".repeat(43) + "+") }
    }

    @Test
    fun `a generated pair is self-consistent and does not leak the verifier in toString`() {
        val pair = Pkce.generate()
        assertEquals(Pkce.challengeFor(pair.verifier), pair.challenge)
        assertEquals("S256", pair.method)
        assertTrue(!pair.toString().contains(pair.verifier))
    }

    /**
     * Regression, and the reason these two now have their own cases.
     *
     * Both delegated to `generateVerifier(24)`, whose `32..96` guard made the call throw
     * unconditionally — neither could ever return a value. Everything above passed throughout,
     * because nothing here had ever called them. They are not incidental helpers: HeliumID
     * accepts an authorization request with no `state` and no `nonce` and never checks either, so
     * these are the only defence a relying party has against callback CSRF and ID-token replay.
     */
    @Test
    fun `state and nonce are produced rather than thrown`() {
        val state = Pkce.generateState()
        val nonce = Pkce.generateNonce()

        // 24 bytes of entropy as unpadded base64url. Not a code verifier, so RFC 7636's 43..128
        // range never applied to them.
        assertEquals(32, state.length, "state was '$state'")
        assertEquals(32, nonce.length, "nonce was '$nonce'")
        assertTrue(state.all { it.isLetterOrDigit() || it in "-._~" }, state)
        assertTrue(nonce.all { it.isLetterOrDigit() || it in "-._~" }, nonce)
    }

    @Test
    fun `state and nonce are not repeated`() {
        val values = List(100) { Pkce.generateState() } + List(100) { Pkce.generateNonce() }

        assertEquals(200, values.toSet().size)
    }
}
