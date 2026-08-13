package dev.kamiql.helium.demo.auth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import java.net.URI
import java.time.Instant

/**
 * Verifies the ID token returned with the authorization code.
 *
 * The SDK deliberately does not do this. Its server plugin verifies *access* tokens, which is a
 * resource server's job; an ID token is a statement made to *this* client about who signed in,
 * and checking it is the client's own responsibility.
 *
 * Skipping it is a real hole, not a formality. The token endpoint is authenticated and reached
 * over TLS, so the token did come from the issuer — but the `nonce` binding is the only thing
 * that ties this particular ID token to the authorization request this app started. Without it
 * an ID token captured from another request for another user can be replayed here.
 */
class IdTokenVerifier(
    issuer: String,
    clientId: String,
    /*
     * Nimbus fetches and caches the key set itself, keyed by `kid`, with its own refresh and
     * rate-limit behaviour. Re-implementing that on top of `HeliumIdClient.jwks()` — which
     * returns the document as raw text precisely so a JOSE library can own it — would mean
     * hand-rolling key rotation.
     *
     * Injectable so tests can supply a fixed key set instead of standing up an HTTP server.
     */
    keys: JWKSource<SecurityContext> =
        JWKSourceBuilder.create<SecurityContext>(URI("$issuer/.well-known/jwks.json").toURL())
            .retrying(true)
            .build(),
) {
    private val processor = DefaultJWTProcessor<SecurityContext>().apply {
        jwsKeySelector = JWSVerificationKeySelector(
            // Pinned to ES256, the only algorithm HeliumID signs with. Accepting whatever the
            // header claims is how `alg: none` and HMAC-with-the-public-key get in.
            JWSAlgorithm.ES256,
            keys,
        )
        jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
            // `aud` of an ID token is the client itself, never the resource server's audience.
            clientId,
            JWTClaimsSet.Builder().issuer(issuer).build(),
            setOf("sub", "iat", "exp"),
        )
    }

    /**
     * @param expectedNonce the value sent with the authorization request.
     * @throws IdTokenInvalid if the signature, the standard claims or the nonce do not hold.
     */
    fun verify(idToken: String, expectedNonce: String): JWTClaimsSet {
        val claims = try {
            processor.process(idToken, null)
        } catch (failure: Exception) {
            throw IdTokenInvalid("The ID token could not be verified.", failure)
        }

        val nonce = claims.getStringClaim("nonce")
        if (nonce != expectedNonce) {
            throw IdTokenInvalid("The ID token's nonce does not match this authorization request.")
        }
        return claims
    }
}

class IdTokenInvalid(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** `auth_time`, when present — how long ago the user actually proved themselves. */
fun JWTClaimsSet.authTime(): Instant? =
    runCatching { getLongClaim("auth_time") }.getOrNull()?.let(Instant::ofEpochSecond)

/** `acr` — `mfa` when a second factor was presented, `pwd` for a single factor. */
fun JWTClaimsSet.authenticationContextClass(): String? =
    runCatching { getStringClaim("acr") }.getOrNull()
