package dev.kamiql.helium.client

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.auth.authenticate
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import java.time.Instant
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * End-to-end verification against a real JWKS endpoint.
 *
 * The negative cases are the point. Offline JWT verification fails open in a very specific way
 * — accept `alg: none`, accept an HMAC signed with the public key, skip `aud` — and each of
 * those is a total authentication bypass rather than a degraded check, so each gets a test.
 */
class TokenVerificationTest {

    private val issuer = "https://id.example"
    private val audience = "orders-api"
    private val signingKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("test-key-1").generate()

    // --- happy path ---------------------------------------------------------------

    @Test
    fun `a well-formed token authenticates and populates the principal`() = protectedApp { client, _ ->
        val token = signToken()
        val response = client.get("/whoami") { bearer(token) }

        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("sub=user-1"), body)
        assertTrue(body.contains("client=orders-web"), body)
        assertTrue(body.contains("scopes=[orders:read, orders:write]"), body)
        assertTrue(body.contains("acr=mfa"), body)
        assertTrue(body.contains("sid=session-9"), body)
    }

    @Test
    fun `a client_credentials token has no user behind it`() = protectedApp { client, _ ->
        val token = signToken(subject = "orders-batch") {
            claim("token_use", "client_credentials")
        }
        val response = client.get("/whoami") { bearer(token) }

        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.bodyAsText().contains("user=null"), response.bodyAsText())
    }

    // --- signature and algorithm confusion ------------------------------------------

    @Test
    fun `alg none is rejected`() = protectedApp { client, _ ->
        val unsigned = PlainJWT(claims().build()).serialize()
        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(unsigned) }.status)
    }

    @Test
    fun `an HMAC token is rejected even when the key id matches`() = protectedApp { client, _ ->
        // The classic confusion attack: sign with HS256 using material the attacker knows, and
        // hope the verifier picks the algorithm out of the header instead of pinning it.
        val hmac = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.HS256).keyID(signingKey.keyID).build(),
            claims().build(),
        ).apply { sign(MACSigner("0123456789abcdef0123456789abcdef".toByteArray())) }.serialize()

        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(hmac) }.status)
    }

    @Test
    fun `a token signed by a different key is rejected`() = protectedApp { client, _ ->
        val foreignKey = ECKeyGenerator(Curve.P_256).keyID(signingKey.keyID).generate()
        val forged = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.keyID).type(JOSEObjectType.JWT).build(),
            claims().build(),
        ).apply { sign(ECDSASigner(foreignKey)) }.serialize()

        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(forged) }.status)
    }

    @Test
    fun `a tampered payload is rejected`() = protectedApp { client, _ ->
        val parts = signToken().split('.')
        val tampered = parts[0] + "." + parts[1].dropLast(2) + "AA." + parts[2]
        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(tampered) }.status)
    }

    // --- claim validation -----------------------------------------------------------

    @Test
    fun `a token for another audience is rejected`() = protectedApp { client, _ ->
        val other = signToken(audience = "billing-api")
        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(other) }.status)
    }

    @Test
    fun `a token from another issuer is rejected`() = protectedApp { client, _ ->
        val other = signToken(issuer = "https://evil.example")
        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(other) }.status)
    }

    @Test
    fun `an expired token is rejected`() = protectedApp { client, _ ->
        val expired = signToken(expiresAt = Instant.now().minusSeconds(600))
        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(expired) }.status)
    }

    @Test
    fun `a not-yet-valid token is rejected`() = protectedApp { client, _ ->
        val future = signToken { notBeforeTime(Date.from(Instant.now().plusSeconds(600))) }
        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(future) }.status)
    }

    @Test
    fun `a token without jti is rejected`() = protectedApp { client, _ ->
        val noJti = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.keyID).type(JOSEObjectType.JWT).build(),
            claims().jwtID(null).build(),
        ).apply { sign(ECDSASigner(signingKey)) }.serialize()

        assertEquals(HttpStatusCode.Unauthorized, client.get("/whoami") { bearer(noJti) }.status)
    }

    // --- authorization gates ---------------------------------------------------------

    @Test
    fun `requireScope admits a caller holding every scope`() = protectedApp { client, _ ->
        val response = client.get("/scoped") { bearer(signToken()) }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `requireScope denies with the forbidden problem code`() = protectedApp { client, _ ->
        val narrow = signToken(scope = "orders:read")
        val response = client.get("/scoped") { bearer(narrow) }

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.headers[HttpHeaders.ContentType]!!.startsWith("application/problem+json"))
        val body = response.bodyAsText()
        assertTrue(body.contains("\"code\":\"forbidden\""), body)
        // The requirement is named; the caller's own scopes are not echoed back.
        assertTrue(body.contains("orders:write"), body)
    }

    @Test
    fun `requireRole reads the configured roles claim`() = protectedApp { client, _ ->
        val admin = signToken { claim("roles", listOf("ADMINISTRATOR")) }
        assertEquals(HttpStatusCode.OK, client.get("/roled") { bearer(admin) }.status)
    }

    @Test
    fun `requireRole denies a token with no roles claim at all`() = protectedApp { client, _ ->
        assertEquals(HttpStatusCode.Forbidden, client.get("/roled") { bearer(signToken()) }.status)
    }

    // --- harness ------------------------------------------------------------------------

    private fun claims(): JWTClaimsSet.Builder {
        val now = Instant.now()
        return JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("user-1")
            .audience(audience)
            .issueTime(Date.from(now))
            .notBeforeTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(300)))
            .jwtID("jti-1")
            .claim("scope", "orders:read orders:write")
            .claim("client_id", "orders-web")
            .claim("amr", listOf("pwd", "otp"))
            .claim("acr", "mfa")
            .claim("sid", "session-9")
    }

    private fun signToken(
        issuer: String = this.issuer,
        subject: String = "user-1",
        audience: String = this.audience,
        scope: String = "orders:read orders:write",
        expiresAt: Instant = Instant.now().plusSeconds(300),
        extra: JWTClaimsSet.Builder.() -> Unit = {},
    ): String {
        val claimSet = claims()
            .issuer(issuer)
            .subject(subject)
            .audience(audience)
            .claim("scope", scope)
            .expirationTime(Date.from(expiresAt))
            .apply(extra)
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(signingKey.keyID)
            .type(JOSEObjectType.JWT)
            .build()
        return SignedJWT(header, claimSet).apply { sign(ECDSASigner(signingKey)) }.serialize()
    }

    private fun io.ktor.client.request.HttpRequestBuilder.bearer(token: String) {
        header(HttpHeaders.Authorization, "Bearer $token")
    }

    /**
     * Runs [block] against an application protected by the plugin, with a live JWKS endpoint.
     *
     * The JWKS server is a real socket on an ephemeral port, because Nimbus fetches it through
     * `HttpURLConnection` — mocking it away would test something other than what ships.
     */
    private fun protectedApp(block: suspend (io.ktor.client.HttpClient, Int) -> Unit) {
        val jwks = JWKSet(listOf(signingKey.toPublicJWK())).toString()
        val jwksServer = embeddedServer(CIO, port = 0) {
            routing {
                get("/.well-known/jwks.json") { call.respondText(jwks, ContentType.Application.Json) }
            }
        }.start(wait = false)

        try {
            val port = runBlocking { jwksServer.engine.resolvedConnectors() }.first().port
            testApplication {
                application {
                    install(HeliumId) {
                        issuer = this@TokenVerificationTest.issuer
                        audience = this@TokenVerificationTest.audience
                        jwks { uri = "http://127.0.0.1:$port/.well-known/jwks.json" }
                    }
                    routing {
                        authenticate("heliumid") {
                            get("/whoami") {
                                val p = call.requireHeliumPrincipal()
                                call.respondText(
                                    "sub=${p.subject} user=${p.userId} client=${p.clientId} " +
                                        "scopes=${p.scopes.sorted()} acr=${p.authenticationContextClass} " +
                                        "sid=${p.sessionId} machine=${p.isServiceClient}",
                                )
                            }
                            requireScope("orders:read", "orders:write") {
                                get("/scoped") { call.respondText("ok") }
                            }
                            requireRole("ADMINISTRATOR") {
                                get("/roled") { call.respondText("ok") }
                            }
                        }
                    }
                }
                block(client, port)
            }
        } finally {
            jwksServer.stop(0, 0)
        }
    }
}
