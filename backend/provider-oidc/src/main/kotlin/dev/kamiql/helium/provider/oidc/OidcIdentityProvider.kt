package dev.kamiql.helium.provider.oidc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.identity.ExternalProfile
import dev.kamiql.helium.domain.identity.Issuer
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.identity.ProviderSubject
import dev.kamiql.helium.spi.AuthorizationRedirect
import dev.kamiql.helium.spi.ExternalIdentityProvider
import dev.kamiql.helium.spi.ProviderAuthorizationRequest
import dev.kamiql.helium.spi.ProviderCallbackRequest
import dev.kamiql.helium.spi.ProviderException
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.forms.submitForm
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/**
 * A generic OIDC relying-party adapter.
 *
 * One instance per configured provider. Google works out of the box via
 * [OidcProviderConfig.google]; any other standards-compliant OIDC provider is a configuration
 * entry, not code.
 *
 * The validation this performs, in order, is the whole reason the adapter exists:
 *
 *  1. `state` is compared against server-side state, so the callback cannot be forged (CSRF);
 *  2. the code is exchanged over TLS with our own client credentials;
 *  3. the ID token's signature is checked against the provider's JWKS;
 *  4. `iss` must equal the **configured** issuer, `aud` must equal our client id;
 *  5. `nonce` must equal the one we generated, so an ID token from a different authorization
 *     request cannot be injected;
 *  6. `sub` is what we link on — never the email (concept §9.4).
 */
class OidcIdentityProvider(
    private val config: OidcProviderConfig,
    private val httpClient: HttpClient,
    private val random: RandomSource,
) : ExternalIdentityProvider {

    private val log = LoggerFactory.getLogger(OidcIdentityProvider::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override val key: ProviderKey = config.key
    override val issuer: Issuer = config.issuer
    override val supportsOidc: Boolean = true

    /**
     * Nimbus JWT processor, wired to the provider's JWKS with Nimbus's own caching and rate
     * limiting.
     *
     * Concept §6.2 forbids hand-rolling JWS validation, and this is why: correct handling of
     * key rollover, `kid` selection and algorithm confusion is subtle, and Nimbus already does
     * it.
     */
    private val jwtProcessor: DefaultJWTProcessor<SecurityContext> by lazy {
        EgressGuard.reject(config.jwksUri, config.allowInsecureTransport)?.let { reason ->
            error("refusing to fetch JWKS for ${config.key}: $reason")
        }
        DefaultJWTProcessor<SecurityContext>().apply {
            val source = JWKSourceBuilder
                .create<SecurityContext>(URI(config.jwksUri).toURL())
                .retrying(true)
                .build()
            jwsKeySelector = JWSVerificationKeySelector(
                // Pin the algorithm set. Accepting whatever the token asks for is how
                // algorithm-confusion attacks get in.
                setOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256),
                source,
            )
            jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
                config.clientId,
                com.nimbusds.jwt.JWTClaimsSet.Builder().issuer(config.issuer.value).build(),
                setOf("sub", "iat", "exp"),
            )
        }
    }

    override suspend fun createAuthorizationRequest(
        request: ProviderAuthorizationRequest,
    ): AuthorizationRedirect {
        val state = random.token(24)
        val nonce = random.token(24)
        val verifier = random.token(32)
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII)),
        )

        val scopes = (config.scopes + request.scopes).joinToString(" ")
        val url = buildString {
            append(config.authorizationEndpoint)
            append(if ('?' in config.authorizationEndpoint) '&' else '?')
            append("response_type=code")
            append("&client_id=").append(encode(config.clientId))
            append("&redirect_uri=").append(encode(request.redirectUri))
            append("&scope=").append(encode(scopes))
            append("&state=").append(encode(state))
            append("&nonce=").append(encode(nonce))
            // PKCE outbound too: it costs nothing and protects the code even against a
            // provider-side redirect leak.
            append("&code_challenge=").append(encode(challenge))
            append("&code_challenge_method=S256")
            request.prompt?.let { append("&prompt=").append(encode(it)) }
        }

        return AuthorizationRedirect(
            authorizationUrl = url,
            pendingState = json.encodeToString(
                PendingState.serializer(),
                PendingState(state = state, nonce = nonce, codeVerifier = verifier, intent = request.intent.name),
            ),
            expiresInSeconds = 600,
        )
    }

    override suspend fun exchangeCode(request: ProviderCallbackRequest): ExternalProfile {
        val pending = runCatching { json.decodeFromString(PendingState.serializer(), request.pendingState) }
            .getOrElse { throw ProviderException("unreadable pending state") }

        // Constant-time compare: `state` is a CSRF token and a timing oracle on it is a real,
        // if slow, attack.
        if (!MessageDigest.isEqual(
                pending.state.toByteArray(StandardCharsets.UTF_8),
                request.state.toByteArray(StandardCharsets.UTF_8),
            )
        ) {
            throw ProviderException("state mismatch")
        }

        EgressGuard.reject(config.tokenEndpoint, config.allowInsecureTransport)?.let {
            throw ProviderException("token endpoint refused by egress policy: $it")
        }

        val response: HttpResponse = try {
            httpClient.submitForm(
                url = config.tokenEndpoint,
                formParameters = Parameters.build {
                    append("grant_type", "authorization_code")
                    append("code", request.code)
                    append("redirect_uri", request.redirectUri)
                    append("client_id", config.clientId)
                    append("client_secret", config.clientSecret.reveal())
                    append("code_verifier", pending.codeVerifier)
                },
            )
        } catch (error: Exception) {
            // Network-shaped failures are retryable; the caller maps them to 503.
            throw ProviderException("token request failed", retryable = true, cause = error)
        }

        if (response.status != HttpStatusCode.OK) {
            // Never log or propagate the body: concept §7.5 forbids storing full provider
            // responses, and error bodies routinely echo the request including the secret.
            log.warn("provider {} token endpoint returned {}", config.key, response.status.value)
            throw ProviderException("token endpoint returned ${response.status.value}")
        }

        val tokens = runCatching { response.body<TokenResponse>() }
            .getOrElse { throw ProviderException("unparseable token response") }

        val idToken = tokens.idToken ?: throw ProviderException("provider returned no id_token")

        val claims = try {
            jwtProcessor.process(idToken, null)
        } catch (error: Exception) {
            log.warn("id token validation failed for provider {}", config.key)
            throw ProviderException("id token validation failed", cause = error)
        }

        // Belt and braces: the processor already checks `iss`, but this is the single most
        // important claim in the exchange and an explicit assertion is cheap.
        if (claims.issuer != config.issuer.value) {
            throw ProviderException("issuer mismatch")
        }
        val tokenNonce = claims.getStringClaim("nonce")
        if (tokenNonce == null || tokenNonce != pending.nonce) {
            throw ProviderException("nonce mismatch")
        }

        val subject = claims.subject?.takeIf { it.isNotBlank() }
            ?: throw ProviderException("id token has no subject")

        return ExternalProfile(
            providerKey = config.key,
            issuer = config.issuer,
            subject = ProviderSubject(subject),
            email = claims.getStringClaim("email")?.let(EmailAddress::parse),
            emailVerified = claims.getBooleanClaim("email_verified") ?: false,
            displayName = claims.getStringClaim("name"),
            username = claims.getStringClaim("preferred_username"),
            // Only scalar, non-sensitive fields, and never a URL that the application might
            // later be tempted to fetch (concept §4.9).
            attributes = buildMap {
                claims.getStringClaim("locale")?.let { put("locale", it) }
                claims.getStringClaim("hd")?.let { put("hosted_domain", it) }
            },
        )
    }

    private fun encode(value: String) = URLEncoder.encode(value, StandardCharsets.UTF_8)

    /** Server-side state for one outbound authorization request. Never sent to the browser. */
    @Serializable
    private data class PendingState(
        val state: String,
        val nonce: String,
        val codeVerifier: String,
        val intent: String,
    )

    @Serializable
    private data class TokenResponse(
        @SerialName("access_token") val accessToken: String? = null,
        @SerialName("id_token") val idToken: String? = null,
        @SerialName("token_type") val tokenType: String? = null,
        @SerialName("expires_in") val expiresIn: Long? = null,
    )
}

