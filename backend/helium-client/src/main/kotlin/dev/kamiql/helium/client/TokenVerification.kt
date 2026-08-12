package dev.kamiql.helium.client

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import java.net.URI
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration

/**
 * The outcome of checking a bearer token.
 *
 * A sealed result rather than a nullable principal: the caller has to decide what to do about
 * each failure shape, and the `WWW-Authenticate` error code differs between them.
 */
internal sealed interface VerificationResult {

    /** The token is valid for this resource server. */
    data class Valid(val principal: HeliumPrincipal) : VerificationResult

    /**
     * The token is not acceptable.
     *
     * @param problemCode the HeliumID error code to report, e.g. `invalid_token`.
     * @param bearerError the RFC 6750 `error` parameter for the `WWW-Authenticate` header.
     * @param detail a fixed, non-sensitive sentence. Never derived from the token.
     */
    data class Rejected(
        val problemCode: String,
        val bearerError: String,
        val detail: String,
    ) : VerificationResult

    /** The token could not be checked — JWKS or introspection was unreachable. */
    data class Unavailable(val detail: String) : VerificationResult
}

/** Anything that can turn a raw bearer token into a [HeliumPrincipal]. */
internal fun interface HeliumTokenVerifier {
    suspend fun verify(token: String, now: Instant): VerificationResult
}

/**
 * Offline ES256 verification against the issuer's JWKS.
 *
 * This is the default and the right choice for almost every resource server: no network hop on
 * the hot path, no availability coupling to the identity server, and no per-request load on it.
 * The cost is revocation latency — a token revoked before it expires keeps verifying until it
 * does, which is why HeliumID keeps access tokens to five minutes (concept §9.2).
 *
 * Three things are pinned deliberately:
 *
 *  * **Algorithm.** Only `ES256` is accepted. Nimbus resolves the key by `kid` *and* algorithm,
 *    so a token claiming `alg: none` finds no selector, and one claiming `HS256` cannot be
 *    verified with an EC public key. That closes the two classic JWT confusion attacks.
 *  * **Issuer.** Exact string match on `iss`. Without it, any server whose JWKS you happen to
 *    fetch can mint tokens for you.
 *  * **Audience.** Exact match on `aud` when configured. Without it, a token minted for a
 *    different service is accepted here — token substitution, and the most commonly skipped
 *    check of the three.
 */
internal class JwksTokenVerifier(
    private val issuer: String,
    private val audience: String?,
    jwksUri: String,
    cacheFor: Duration,
    refreshTimeout: Duration,
    rateLimitFor: Duration,
    connectTimeout: Duration,
    readTimeout: Duration,
    jwksSizeLimit: Int,
    clockSkew: Duration,
    private val rolesClaim: String,
) : HeliumTokenVerifier {

    private val jwkSource: JWKSource<SecurityContext> = JWKSourceBuilder
        .create<SecurityContext>(
            URI(jwksUri).toURL(),
            DefaultResourceRetriever(
                connectTimeout.inWholeMilliseconds.toInt(),
                readTimeout.inWholeMilliseconds.toInt(),
                jwksSizeLimit,
            ),
        )
        // Serve from cache for `cacheFor`; when it expires, one thread refreshes and the rest
        // wait up to `refreshTimeout` rather than stampeding the identity server.
        .cache(cacheFor.inWholeMilliseconds, refreshTimeout.inWholeMilliseconds)
        // An unknown `kid` triggers at most one refresh per interval. Without this, a stream of
        // tokens with forged key ids becomes an amplified DoS against the JWKS endpoint.
        .rateLimited(rateLimitFor.inWholeMilliseconds)
        .retrying(true)
        .build()

    private val processor = DefaultJWTProcessor<SecurityContext>().apply {
        // HeliumID signs access tokens with `typ: JWT`; `at+jwt` (RFC 9068) is accepted so a
        // future issuer change does not break verifiers. Anything else is refused.
        jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(
            JOSEObjectType.JWT,
            JOSEObjectType("at+jwt"),
            null,
        )
        jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.ES256, jwkSource)
        jwtClaimsSetVerifier = DefaultJWTClaimsVerifier<SecurityContext>(
            /* acceptedAudience = */ audience?.let { setOf(it) },
            /* exactMatchClaims = */ JWTClaimsSet.Builder().issuer(issuer).build(),
            /* requiredClaims = */ setOf("sub", "exp", "jti"),
            /* prohibitedClaims = */ null,
        ).apply {
            maxClockSkew = clockSkew.inWholeSeconds.toInt()
        }
    }

    override suspend fun verify(token: String, now: Instant): VerificationResult = try {
        val claims = processor.process(token, null)
        VerificationResult.Valid(claims.toHeliumPrincipal(rolesClaim))
    } catch (failure: com.nimbusds.jose.KeySourceException) {
        // JWKS could not be retrieved. The token itself may be perfectly fine, so this is a
        // 503, not a 401 — answering "invalid token" would send clients into a pointless
        // re-authentication loop during an outage of the identity server.
        VerificationResult.Unavailable("The signing keys could not be retrieved.")
    } catch (failure: Exception) {
        // Every other failure — bad signature, wrong issuer, wrong audience, expired, unknown
        // key, wrong algorithm — collapses to one answer on purpose. Telling a caller *why*
        // their forged token failed is free debugging for an attacker.
        VerificationResult.Rejected(
            problemCode = "invalid_token",
            bearerError = "invalid_token",
            detail = "The token is not valid.",
        )
    }
}

/**
 * Verification via the issuer's `/oauth2/introspect` endpoint (RFC 7662).
 *
 * Opt-in, and a real trade-off rather than a strict upgrade:
 *
 *  * **You gain** immediate revocation. The deny list is consulted on every call, so a revoked
 *    token stops working within [cacheFor] instead of within its remaining lifetime.
 *  * **You pay** a network round trip on the request path, and your availability becomes a
 *    function of the identity server's. This verifier fails **closed** — an unreachable
 *    identity server means 503, not "assume valid" — which is the only safe default but does
 *    mean a hard dependency.
 *
 * Cache entries are keyed on a SHA-256 of the token, never the token itself, and never outlive
 * the token's own `exp`.
 */
internal class IntrospectionTokenVerifier(
    private val client: HeliumIdClient,
    private val clientId: String,
    private val clientSecret: String,
    private val expectedIssuer: String,
    private val expectedAudience: String?,
    private val cacheFor: Duration,
    private val delegate: HeliumTokenVerifier?,
) : HeliumTokenVerifier {

    private data class CacheEntry(val result: VerificationResult, val validUntil: Instant)

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    override suspend fun verify(token: String, now: Instant): VerificationResult {
        val key = sha256(token)
        cache[key]?.let { if (it.validUntil.isAfter(now)) return it.result }

        // Verify the signature offline first when we can: it rejects garbage without spending a
        // round trip, and it means introspection only ever sees structurally valid tokens.
        delegate?.verify(token, now)?.let { if (it !is VerificationResult.Valid) return it }

        val response = try {
            client.introspect(token, clientId, clientSecret)
        } catch (failure: HeliumTransportException) {
            return VerificationResult.Unavailable("The identity server could not be reached.")
        } catch (failure: HeliumApiException) {
            return VerificationResult.Unavailable("Token introspection failed.")
        }

        val result = response.toVerificationResult(expectedIssuer, expectedAudience)

        // Never cache past the token's own expiry, and never cache a transient failure.
        if (result !is VerificationResult.Unavailable) {
            val tokenExpiry = response.exp?.let(Instant::ofEpochSecond)
            val ceiling = now.plusSeconds(cacheFor.inWholeSeconds)
            val validUntil = if (tokenExpiry != null && tokenExpiry.isBefore(ceiling)) tokenExpiry else ceiling
            if (validUntil.isAfter(now)) cache[key] = CacheEntry(result, validUntil)
        }
        pruneExpired(now)
        return result
    }

    /** Bounded memory: entries are dropped once they can no longer be served. */
    private fun pruneExpired(now: Instant) {
        if (cache.size < PRUNE_THRESHOLD) return
        cache.entries.removeIf { !it.value.validUntil.isAfter(now) }
    }

    private fun sha256(value: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    private companion object {
        const val PRUNE_THRESHOLD = 1024
    }
}

/**
 * Turns an introspection response into a principal.
 *
 * The issuer and audience are re-checked here even though the identity server already vouched
 * for the token: introspection tells you a token is active, not that it was minted for *you*.
 */
private fun IntrospectionResponse.toVerificationResult(
    expectedIssuer: String,
    expectedAudience: String?,
): VerificationResult {
    val rejected = VerificationResult.Rejected(
        problemCode = "invalid_token",
        bearerError = "invalid_token",
        detail = "The token is not valid.",
    )
    if (!active) return rejected
    if (iss != null && iss != expectedIssuer) return rejected
    if (expectedAudience != null && aud?.contains(expectedAudience) != true) return rejected

    val subject = sub ?: return rejected
    val expiry = exp?.let(Instant::ofEpochSecond) ?: return rejected

    return VerificationResult.Valid(
        HeliumPrincipal(
            subject = subject,
            // Introspection does not report `token_use`, so a machine token is identified by
            // its subject matching its client id — the shape the issuer mints.
            userId = subject.takeUnless { it == clientId },
            clientId = clientId,
            scopes = scope?.split(' ')?.filter { it.isNotBlank() }?.toSet().orEmpty(),
            roles = emptySet(),
            authenticationMethods = emptySet(),
            authenticationContextClass = null,
            sessionId = null,
            tokenId = jti ?: "",
            audience = aud.orEmpty().toSet(),
            issuedAt = iat?.let(Instant::ofEpochSecond),
            expiresAt = expiry,
        ),
    )
}

/**
 * Projects a verified claim set onto [HeliumPrincipal].
 *
 * Unknown claims are dropped rather than carried in a map: a resource server that reads an
 * arbitrary claim is one deployment change away from a bug, and the claim set that matters is
 * fixed by concept §4.2.
 */
private fun JWTClaimsSet.toHeliumPrincipal(rolesClaim: String): HeliumPrincipal {
    val subject = subject ?: ""
    val isMachineToken = getStringClaim("token_use") == "client_credentials"
    return HeliumPrincipal(
        subject = subject,
        userId = subject.takeUnless { isMachineToken || it.isEmpty() },
        clientId = getStringClaim("client_id"),
        scopes = getStringClaim("scope")?.split(' ')?.filter { it.isNotBlank() }?.toSet().orEmpty(),
        roles = stringListClaimOrEmpty(rolesClaim),
        authenticationMethods = stringListClaimOrEmpty("amr"),
        authenticationContextClass = getStringClaim("acr"),
        sessionId = getStringClaim("sid"),
        tokenId = jwtid ?: "",
        audience = audience.orEmpty().toSet(),
        issuedAt = issueTime?.toInstant(),
        expiresAt = expirationTime.toInstant(),
    )
}

/** Reads a claim that may legitimately be absent, a single string, or an array of strings. */
private fun JWTClaimsSet.stringListClaimOrEmpty(name: String): Set<String> {
    runCatching { getStringListClaim(name) }.getOrNull()?.let { return it.toSet() }
    runCatching { getStringClaim(name) }.getOrNull()?.let { return setOf(it) }
    return emptySet()
}
