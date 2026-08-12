package dev.kamiql.helium.provider.oidc

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.Secret
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
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.LoggerFactory
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/**
 * Configuration for a plain OAuth 2 provider — one that has no ID token and no OIDC discovery.
 *
 * Concept §6.3 is explicit about this: "Treat GitHub as a provider API integration rather than
 * assuming every provider behaves like OIDC." GitHub and Discord both fall here. The practical
 * consequence is that identity comes from an authenticated API call rather than from a signed
 * assertion, so the transport *is* the security boundary — there is no signature to fall back on
 * if TLS is wrong.
 *
 * @param issuer a constant this deployment assigns, not something the provider tells us. It is
 *        the stable half of the `(issuer, subject)` linking key and must never change once
 *        identities exist, or every linked account silently detaches.
 * @param usePkce some providers reject unknown authorization parameters. GitHub's classic OAuth
 *        apps ignore PKCE entirely, so sending it buys nothing; Discord honours it.
 * @param userInfoHeaders provider-specific requirements — GitHub rejects requests without a
 *        `User-Agent` and wants its own `Accept`.
 */
data class OAuth2ApiProviderConfig(
    val key: ProviderKey,
    val displayName: String,
    val issuer: Issuer,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val userInfoEndpoint: String,
    val clientId: String,
    val clientSecret: Secret,
    val scopes: Set<String>,
    val usePkce: Boolean = true,
    val userInfoHeaders: Map<String, String> = emptyMap(),
    val allowInsecureTransport: Boolean = false,
) {
    init {
        listOf(authorizationEndpoint, tokenEndpoint, userInfoEndpoint).forEach { endpoint ->
            require(allowInsecureTransport || endpoint.startsWith("https://")) {
                "provider ${key.value} endpoint must use https: $endpoint"
            }
        }
    }
}

/** What a profile mapper is given: the parsed user document plus a way to ask follow-up questions. */
class ProfileContext(
    val http: HttpClient,
    val accessToken: String,
    val json: Json,
    val config: OAuth2ApiProviderConfig,
) {
    /**
     * Performs an authenticated GET against the provider.
     *
     * Only for URLs built from [OAuth2ApiProviderConfig], never from a value found in a profile
     * document — concept §4.9: "Never fetch user-controlled URLs from provider profile fields."
     */
    suspend fun getJson(url: String): JsonObject? = fetch(url)?.jsonObject

    suspend fun getJsonArray(url: String): JsonArray? = fetch(url) as? JsonArray

    private suspend fun fetch(url: String): kotlinx.serialization.json.JsonElement? {
        EgressGuard.reject(url, config.allowInsecureTransport)?.let {
            throw ProviderException("endpoint refused by egress policy: $it")
        }
        val response = http.get(url) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
            header(HttpHeaders.Accept, "application/json")
            config.userInfoHeaders.forEach { (name, value) -> header(name, value) }
        }
        if (response.status != HttpStatusCode.OK) return null
        return runCatching { json.parseToJsonElement(response.bodyAsText()) }.getOrNull()
    }
}

/** Turns a provider's own user document into the normalized [ExternalProfile]. */
fun interface ProfileMapper {
    suspend fun map(context: ProfileContext, userInfo: JsonObject): ExternalProfile
}

/**
 * Adapter for OAuth 2 providers that expose identity through an API rather than an ID token.
 *
 * The validation it can perform is necessarily weaker than the OIDC adapter's — there is no
 * signature and no `nonce`, because there is no token to sign. What remains, and what this class
 * enforces, is: a single-use `state` compared in constant time, an exact configured token
 * endpoint reached over TLS with no redirect following, and a subject taken from the provider's
 * own immutable identifier.
 *
 * That last point is the one that bites people. A GitHub *login* and a Discord *username* are
 * both renameable, and linking on either means the account silently detaches — or worse, attaches
 * to whoever claims the freed name next. Only the numeric id is stable.
 */
class OAuth2ApiIdentityProvider(
    private val config: OAuth2ApiProviderConfig,
    private val httpClient: HttpClient,
    private val random: RandomSource,
    private val profileMapper: ProfileMapper,
) : ExternalIdentityProvider {

    private val log = LoggerFactory.getLogger(OAuth2ApiIdentityProvider::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override val key: ProviderKey = config.key
    override val issuer: Issuer = config.issuer
    override val supportsOidc: Boolean = false

    override suspend fun createAuthorizationRequest(
        request: ProviderAuthorizationRequest,
    ): AuthorizationRedirect {
        val state = random.token(24)
        val verifier = if (config.usePkce) random.token(32) else null

        val url = buildString {
            append(config.authorizationEndpoint)
            append(if ('?' in config.authorizationEndpoint) '&' else '?')
            append("response_type=code")
            append("&client_id=").append(encode(config.clientId))
            append("&redirect_uri=").append(encode(request.redirectUri))
            append("&scope=").append(encode((config.scopes + request.scopes).joinToString(" ")))
            append("&state=").append(encode(state))
            if (verifier != null) {
                append("&code_challenge=").append(encode(challengeFor(verifier)))
                append("&code_challenge_method=S256")
            }
            request.prompt?.let { append("&prompt=").append(encode(it)) }
        }

        return AuthorizationRedirect(
            authorizationUrl = url,
            pendingState = json.encodeToString(
                PendingState.serializer(),
                PendingState(state = state, codeVerifier = verifier, intent = request.intent.name),
            ),
            expiresInSeconds = 600,
        )
    }

    override suspend fun exchangeCode(request: ProviderCallbackRequest): ExternalProfile {
        val pending = runCatching { json.decodeFromString(PendingState.serializer(), request.pendingState) }
            .getOrElse { throw ProviderException("unreadable pending state") }

        // `state` is the only CSRF protection this flow has — there is no nonce to fall back on.
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
                    pending.codeVerifier?.let { append("code_verifier", it) }
                },
            ) {
                // GitHub answers form-encoded unless asked otherwise, which would parse as an
                // empty token response and fail much later with a confusing message.
                header(HttpHeaders.Accept, "application/json")
            }
        } catch (error: Exception) {
            throw ProviderException("token request failed", retryable = true, cause = error)
        }

        if (response.status != HttpStatusCode.OK) {
            // The body routinely echoes the request, including the client secret, so it is
            // neither logged nor propagated (concept §7.5).
            log.warn("provider {} token endpoint returned {}", config.key, response.status.value)
            throw ProviderException("token endpoint returned ${response.status.value}")
        }

        val tokens = runCatching { response.body<TokenResponse>() }
            .getOrElse { throw ProviderException("unparseable token response") }
        val accessToken = tokens.accessToken
            ?: throw ProviderException("provider returned no access_token")

        val context = ProfileContext(httpClient, accessToken, json, config)
        val userInfo = context.getJson(config.userInfoEndpoint)
            ?: throw ProviderException("user endpoint returned no usable document")

        val profile = profileMapper.map(context, userInfo)
        if (profile.subject.value.isBlank()) {
            throw ProviderException("provider returned no subject")
        }
        return profile
    }

    private fun encode(value: String) = URLEncoder.encode(value, StandardCharsets.UTF_8)

    private fun challengeFor(verifier: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII)),
        )

    @Serializable
    private data class PendingState(
        val state: String,
        val codeVerifier: String?,
        val intent: String,
    )

    @Serializable
    private data class TokenResponse(
        @SerialName("access_token") val accessToken: String? = null,
        @SerialName("token_type") val tokenType: String? = null,
        val scope: String? = null,
    )
}

// --- concrete providers ---------------------------------------------------------------------

/**
 * GitHub.
 *
 * Two quirks are handled here and nowhere else, which is the point of keeping adapters separate:
 *
 *  * the primary email is **not** in `/user` unless the account made it public, so it takes a
 *    second call to `/user/emails`;
 *  * `login` is renameable and gets reassigned to other people, so the numeric `id` is the only
 *    safe subject.
 */
fun gitHubProvider(
    clientId: String,
    clientSecret: Secret,
    httpClient: HttpClient,
    random: RandomSource,
): OAuth2ApiIdentityProvider = OAuth2ApiIdentityProvider(
    config = OAuth2ApiProviderConfig(
        key = ProviderKey("github"),
        displayName = "GitHub",
        issuer = Issuer("https://github.com"),
        authorizationEndpoint = "https://github.com/login/oauth/authorize",
        tokenEndpoint = "https://github.com/login/oauth/access_token",
        userInfoEndpoint = "https://api.github.com/user",
        clientId = clientId,
        clientSecret = clientSecret,
        // `user:email` is what makes the /user/emails call below possible.
        scopes = setOf("read:user", "user:email"),
        // Classic OAuth apps ignore PKCE; sending it would be theatre.
        usePkce = false,
        userInfoHeaders = mapOf(
            "Accept" to "application/vnd.github+json",
            "X-GitHub-Api-Version" to "2022-11-28",
            // GitHub rejects API requests without one.
            "User-Agent" to "HeliumID",
        ),
    ),
    httpClient = httpClient,
    random = random,
) { context, user ->
    // `/user.email` is the *public profile* address, which GitHub does not promise is verified.
    // Prefer the emails endpoint, which says so explicitly.
    val verifiedEmail = context.primaryVerifiedGitHubEmail()
    val publicEmail = user.stringOrNull("email")?.let(EmailAddress::parse)

    ExternalProfile(
        providerKey = ProviderKey("github"),
        issuer = Issuer("https://github.com"),
        // Numeric id, never `login`.
        subject = ProviderSubject(user.scalarOrNull("id").orEmpty()),
        email = verifiedEmail?.first ?: publicEmail,
        emailVerified = verifiedEmail?.second ?: false,
        displayName = user.stringOrNull("name"),
        username = user.stringOrNull("login"),
        attributes = emptyMap(),
    )
}

/**
 * Fetches the primary, verified address from `/user/emails`.
 *
 * Returns the verified flag alongside it: an unverified provider email is displayed but never
 * treated as proof of anything (concept §9.4).
 */
private suspend fun ProfileContext.primaryVerifiedGitHubEmail(): Pair<EmailAddress, Boolean>? {
    val emails = getJsonArray("https://api.github.com/user/emails") ?: return null
    val primary = emails.filterIsInstance<JsonObject>()
        .firstOrNull { it.booleanOrNull("primary") == true && it.booleanOrNull("verified") == true }
        ?: emails.filterIsInstance<JsonObject>().firstOrNull { it.booleanOrNull("verified") == true }
        ?: return null
    val address = primary.stringOrNull("email")?.let(EmailAddress::parse) ?: return null
    return address to (primary.booleanOrNull("verified") ?: false)
}

/**
 * Discord.
 *
 * Closer to standard than GitHub — it supports PKCE and returns the email inline — but it is
 * still not OIDC: there is no ID token, so the profile is only as trustworthy as the TLS
 * connection that carried it.
 */
fun discordProvider(
    clientId: String,
    clientSecret: Secret,
    httpClient: HttpClient,
    random: RandomSource,
): OAuth2ApiIdentityProvider = OAuth2ApiIdentityProvider(
    config = OAuth2ApiProviderConfig(
        key = ProviderKey("discord"),
        displayName = "Discord",
        issuer = Issuer("https://discord.com"),
        authorizationEndpoint = "https://discord.com/oauth2/authorize",
        tokenEndpoint = "https://discord.com/api/oauth2/token",
        userInfoEndpoint = "https://discord.com/api/users/@me",
        clientId = clientId,
        clientSecret = clientSecret,
        scopes = setOf("identify", "email"),
        usePkce = true,
    ),
    httpClient = httpClient,
    random = random,
) { _, user ->
    ExternalProfile(
        providerKey = ProviderKey("discord"),
        issuer = Issuer("https://discord.com"),
        // The snowflake id. `username` is changeable and was globally re-namespaced in 2023.
        subject = ProviderSubject(user.scalarOrNull("id").orEmpty()),
        email = user.stringOrNull("email")?.let(EmailAddress::parse),
        // Discord's `verified` is about the account's own email confirmation.
        emailVerified = user.booleanOrNull("verified") ?: false,
        displayName = user.stringOrNull("global_name") ?: user.stringOrNull("username"),
        username = user.stringOrNull("username"),
        attributes = emptyMap(),
    )
}

// --- lenient JSON access -----------------------------------------------------------------------
//
// Provider documents are external input: a field can be absent, null, or a different type than
// last month. These helpers return null rather than throwing, so a provider changing a field
// shape degrades the profile instead of taking the callback down.

private fun JsonObject.stringOrNull(name: String): String? =
    (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }

/** Reads a scalar as text, so a numeric id and a string id are handled identically. */
private fun JsonObject.scalarOrNull(name: String): String? =
    (this[name] as? JsonPrimitive)?.content?.takeIf { it.isNotBlank() && it != "null" }

private fun JsonObject.booleanOrNull(name: String): Boolean? =
    (this[name] as? JsonPrimitive)?.jsonPrimitive?.content?.toBooleanStrictOrNull()
