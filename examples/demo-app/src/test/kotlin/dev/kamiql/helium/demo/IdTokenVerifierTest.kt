package dev.kamiql.helium.demo

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.kamiql.helium.demo.auth.IdTokenInvalid
import dev.kamiql.helium.demo.auth.IdTokenVerifier
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * ID-token verification, which the SDK deliberately leaves to the client.
 *
 * The nonce case is the one that matters. Signature, issuer and audience prove the token came
 * from HeliumID for this client — they do not prove it was minted for *this* sign-in. Without the
 * nonce binding, an ID token captured from another authorization request can be replayed here and
 * the application will happily sign that user in.
 */
class IdTokenVerifierTest {

    private val issuer = "https://id.example"
    private val clientId = "helium-demo"
    private val nonce = "nonce-from-this-request"

    private val signingKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("test-key").generate()

    private val verifier = IdTokenVerifier(
        issuer = issuer,
        clientId = clientId,
        keys = ImmutableJWKSet<SecurityContext>(JWKSet(signingKey.toPublicJWK())),
    )

    private fun idToken(
        issuer: String = this.issuer,
        audience: String = clientId,
        nonce: String? = this.nonce,
        subject: String = "user-1",
        expiresInSeconds: Long = 300,
        key: ECKey = signingKey,
    ): String {
        val now = System.currentTimeMillis()
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .subject(subject)
            .issueTime(Date(now))
            .expirationTime(Date(now + expiresInSeconds * 1000))
            .claim("acr", "pwd")
            .apply { nonce?.let { claim("nonce", it) } }
            .build()

        return SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.keyID).type(JOSEObjectType.JWT).build(),
            claims,
        ).apply { sign(ECDSASigner(key)) }.serialize()
    }

    @Test
    fun `a well-formed token verifies and yields its claims`() {
        val claims = verifier.verify(idToken(), nonce)

        assertEquals("user-1", claims.subject)
        assertEquals("pwd", claims.getStringClaim("acr"))
    }

    @Test
    fun `a token minted for a different authorization request is rejected`() {
        assertFailsWith<IdTokenInvalid> { verifier.verify(idToken(nonce = "some-other-nonce"), nonce) }
    }

    /** A missing nonce must fail closed, not be treated as "nothing to compare". */
    @Test
    fun `a token with no nonce is rejected`() {
        assertFailsWith<IdTokenInvalid> { verifier.verify(idToken(nonce = null), nonce) }
    }

    @Test
    fun `a token from another issuer is rejected`() {
        assertFailsWith<IdTokenInvalid> { verifier.verify(idToken(issuer = "https://evil.example"), nonce) }
    }

    /** An ID token's audience is the client, so another client's token must not authenticate here. */
    @Test
    fun `a token for another client is rejected`() {
        assertFailsWith<IdTokenInvalid> { verifier.verify(idToken(audience = "another-app"), nonce) }
    }

    @Test
    fun `an expired token is rejected`() {
        assertFailsWith<IdTokenInvalid> { verifier.verify(idToken(expiresInSeconds = -60), nonce) }
    }

    /**
     * The signature is checked against the published key set, not merely parsed. A token signed
     * by a key the issuer never published is a forgery.
     */
    @Test
    fun `a token signed by an unknown key is rejected`() {
        val foreign = ECKeyGenerator(Curve.P_256).keyID("test-key").generate()

        assertFailsWith<IdTokenInvalid> { verifier.verify(idToken(key = foreign), nonce) }
    }
}
