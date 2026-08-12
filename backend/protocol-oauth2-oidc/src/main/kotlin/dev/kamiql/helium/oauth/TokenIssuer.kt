package dev.kamiql.helium.oauth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.user.User
import org.slf4j.LoggerFactory
import java.time.Instant
import java.util.Date

/**
 * Mints and verifies signed tokens.
 *
 * Access tokens are ES256 JWTs so that subsidiary APIs verify them offline against JWKS —
 * no introspection round trip on every request (concept §9.2). Revocation before expiry is
 * handled by the `/introspect` deny list, which is why access tokens are kept to five minutes.
 *
 * Claims are the §4.2 set and nothing more. In particular, no email, no name and no roles: an
 * access token is a bearer credential that lands in logs and proxies, and every extra claim is
 * data leaked to everywhere it travels.
 */
class TokenIssuer(
    private val issuer: String,
    private val keys: SigningKeyService,
    private val random: RandomSource,
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
) {

    private val log = LoggerFactory.getLogger(TokenIssuer::class.java)

    /** A minted access token plus what the caller needs to describe it. */
    data class IssuedAccessToken(
        val token: String,
        val tokenId: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
    )

    suspend fun issueAccessToken(
        userId: UserId?,
        client: OAuthClient,
        scopes: Set<String>,
        methods: Set<AuthenticationMethod>,
        sessionId: SessionId?,
        now: Instant,
    ): IssuedAccessToken {
        val signingKey = keys.activeSigningKey(now)
        val expiresAt = now.plus(lifetimes.accessToken)
        val tokenId = random.token(16)

        // `amr` is the truth about how the subject authenticated; `acr` summarizes it so a
        // resource server can make a step-up decision without parsing the method list.
        val secondFactorUsed = methods.any { it.isSecondFactor }

        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(userId?.value?.toString() ?: client.clientId.value)
            .audience(client.audiences.toList().ifEmpty { listOf(client.clientId.value) })
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiresAt))
            .notBeforeTime(Date.from(now))
            .jwtID(tokenId)
            .claim("scope", scopes.sorted().joinToString(" "))
            .claim("client_id", client.clientId.value)
            .apply {
                if (methods.isNotEmpty()) claim("amr", methods.map { it.amr }.distinct())
                claim("acr", if (secondFactorUsed) ACR_MFA else ACR_PASSWORD)
                // Lets a resource server correlate a token with the browser session that
                // produced it, and lets introspection report session revocation.
                sessionId?.let { claim("sid", it.value.toString()) }
                if (userId == null) claim("token_use", "client_credentials")
            }
            .build()

        return IssuedAccessToken(
            token = sign(signingKey, claims),
            tokenId = tokenId,
            issuedAt = now,
            expiresAt = expiresAt,
        )
    }

    /**
     * OIDC ID token.
     *
     * Unlike the access token this *is* about the user, so it carries profile claims — but only
     * those the granted scopes cover. `nonce` is echoed back verbatim so the client can bind
     * the token to its own authorization request.
     */
    suspend fun issueIdToken(
        user: User,
        client: OAuthClient,
        scopes: Set<String>,
        nonce: String?,
        methods: Set<AuthenticationMethod>,
        authenticatedAt: Instant,
        now: Instant,
    ): String {
        val signingKey = keys.activeSigningKey(now)
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(user.id.value.toString())
            // The ID token's audience is the client itself, never the resource server.
            .audience(client.clientId.value)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plus(lifetimes.idToken)))
            .claim("auth_time", authenticatedAt.epochSecond)
            .apply {
                nonce?.let { claim("nonce", it) }
                claim("amr", methods.map { it.amr }.distinct())
                claim("acr", if (methods.any { it.isSecondFactor }) ACR_MFA else ACR_PASSWORD)

                if (Scope.PROFILE in scopes) {
                    claim("name", user.displayName)
                    claim("preferred_username", user.username.display)
                    claim("given_name", user.firstName)
                    claim("family_name", user.lastName)
                    claim("updated_at", user.updatedAt.epochSecond)
                }
                if (Scope.EMAIL in scopes) {
                    claim("email", user.primaryEmail.display)
                    claim("email_verified", user.isEmailVerified)
                }
            }
            .build()

        return sign(signingKey, claims)
    }

    /**
     * Verifies a token's signature and standard claims.
     *
     * Deliberately does **not** consult the revocation list — that is the introspection
     * endpoint's job and requires a database read. This is the cheap, offline half.
     *
     * @return the parsed claims, or `null` when anything at all is wrong. Callers get no detail
     *         about which check failed; the reason is logged at debug and nowhere else.
     */
    suspend fun verify(token: String, expectedAudience: String? = null, now: Instant): VerifiedToken? {
        val jwt = runCatching { SignedJWT.parse(token) }.getOrNull() ?: return null
        val kid = jwt.header.keyID ?: return null
        val key = keys.verificationKey(kid) ?: return null

        if (jwt.header.algorithm != JWSAlgorithm.ES256) {
            // Refuse to let the token choose its own algorithm. `alg: none` and HS256-with-the-
            // public-key are the classic JWT forgeries, and both die here.
            log.debug("rejected token with unexpected algorithm {}", jwt.header.algorithm)
            return null
        }

        if (!jwt.verify(ECDSAVerifier(key.toECPublicKey()))) return null

        val claims = jwt.jwtClaimsSet
        if (claims.issuer != issuer) return null
        if (claims.expirationTime == null || claims.expirationTime.toInstant().isBefore(now)) return null
        claims.notBeforeTime?.let { if (now.isBefore(it.toInstant())) return null }
        if (expectedAudience != null && expectedAudience !in claims.audience) return null

        return VerifiedToken(
            tokenId = claims.jwtid ?: return null,
            subject = claims.subject,
            clientId = claims.getStringClaim("client_id")?.let(::ClientId),
            scopes = claims.getStringClaim("scope")?.split(' ')?.filter { it.isNotBlank() }?.toSet().orEmpty(),
            audience = claims.audience.toSet(),
            sessionId = claims.getStringClaim("sid")?.let(SessionId::parse),
            authenticationMethods = (claims.getStringListClaim("amr") ?: emptyList())
                .mapNotNull(AuthenticationMethod::fromAmr).toSet(),
            issuedAt = claims.issueTime?.toInstant() ?: now,
            expiresAt = claims.expirationTime.toInstant(),
        )
    }

    private fun sign(key: LoadedSigningKey, claims: JWTClaimsSet): String {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(key.id.value)
            .type(com.nimbusds.jose.JOSEObjectType.JWT)
            .build()
        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(key.key))
        return jwt.serialize()
    }

    companion object {
        /** Authentication context: a single factor. */
        const val ACR_PASSWORD: String = "pwd"

        /** Authentication context: a second factor was presented. */
        const val ACR_MFA: String = "mfa"
    }
}

/** Claims extracted from a token that passed signature and time validation. */
data class VerifiedToken(
    val tokenId: String,
    val subject: String,
    val clientId: ClientId?,
    val scopes: Set<String>,
    val audience: Set<String>,
    val sessionId: SessionId?,
    val authenticationMethods: Set<AuthenticationMethod>,
    val issuedAt: Instant,
    val expiresAt: Instant,
) {
    val userId: UserId? get() = UserId.parse(subject)
}
