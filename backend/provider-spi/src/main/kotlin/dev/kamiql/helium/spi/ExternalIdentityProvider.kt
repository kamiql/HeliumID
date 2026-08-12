package dev.kamiql.helium.spi

import dev.kamiql.helium.domain.identity.ExternalProfile
import dev.kamiql.helium.domain.identity.Issuer
import dev.kamiql.helium.domain.identity.ProviderKey

/**
 * An external OAuth 2 / OIDC identity provider.
 *
 * One adapter per provider. Provider quirks — GitHub's separate `/user/emails` call, Discord's
 * non-standard scopes, Google's discovery document — live inside the adapter and stop there.
 * The domain only ever sees an [ExternalProfile].
 *
 * Implementations must, without exception:
 *
 *  * take every endpoint from configuration, never from client input (concept §4.9 SSRF);
 *  * generate and verify `state`, PKCE and, for OIDC, `nonce`;
 *  * verify the ID token signature, `iss`, `aud` and `exp` against the configured issuer;
 *  * refuse to follow redirects and refuse plaintext HTTP outside local development;
 *  * never fetch a URL taken from a provider profile field.
 */
interface ExternalIdentityProvider {

    val key: ProviderKey

    /** The issuer this adapter will accept, and nothing else. */
    val issuer: Issuer

    /** True for real OIDC providers; false for OAuth-only APIs such as GitHub. */
    val supportsOidc: Boolean

    /**
     * Builds the URL to send the browser to.
     *
     * The returned [AuthorizationRedirect.pendingState] holds everything needed to validate
     * the callback and is stored server side under a single-use handle — never in a cookie the
     * client could tamper with.
     */
    suspend fun createAuthorizationRequest(request: ProviderAuthorizationRequest): AuthorizationRedirect

    /**
     * Exchanges the callback code for a verified profile.
     *
     * @throws ProviderException on any protocol, network or validation failure. Callers map it
     *         to `provider_unavailable` or `provider_invalid_response`; the underlying detail
     *         is logged, never returned.
     */
    suspend fun exchangeCode(request: ProviderCallbackRequest): ExternalProfile
}

/**
 * @param redirectUri **our** callback URI, already validated against configuration.
 * @param scopes requested provider scopes; the adapter adds whatever it needs for identity.
 * @param prompt optional OIDC `prompt`, e.g. `consent` when re-linking.
 */
data class ProviderAuthorizationRequest(
    val redirectUri: String,
    val scopes: Set<String> = emptySet(),
    val prompt: String? = null,
    /** Distinguishes "sign in" from "link to the account I am already signed in as". */
    val intent: ProviderIntent = ProviderIntent.SIGN_IN,
)

enum class ProviderIntent { SIGN_IN, LINK }

/**
 * @param pendingState opaque, adapter-owned state (`state`, PKCE verifier, `nonce`). Stored in
 *        the [dev.kamiql.helium.flow.port.SecurityTransactionStore] with a short TTL and read
 *        back exactly once.
 */
data class AuthorizationRedirect(
    val authorizationUrl: String,
    val pendingState: String,
    val expiresInSeconds: Long,
)

/**
 * @param code the `code` query parameter.
 * @param state the `state` query parameter as returned by the provider; the adapter compares
 *        it against [pendingState] rather than trusting it.
 */
data class ProviderCallbackRequest(
    val code: String,
    val state: String,
    val redirectUri: String,
    val pendingState: String,
)

/**
 * Anything an adapter can go wrong with.
 *
 * @param retryable distinguishes "the provider is down" (503, safe to retry) from "the
 *        provider said no" (do not retry).
 */
class ProviderException(
    message: String,
    val retryable: Boolean = false,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Registry of the configured provider adapters.
 *
 * Lookup is by key and unknown keys are rejected — this is the "configured provider registry"
 * concept §4.9 calls for, and it is what stops a request from naming an arbitrary provider.
 */
class ProviderRegistry(providers: List<ExternalIdentityProvider>) {

    private val byKey = providers.associateBy { it.key }

    operator fun get(key: ProviderKey): ExternalIdentityProvider? = byKey[key]

    /** Providers the login UI may offer. */
    val available: List<ProviderKey> get() = byKey.keys.toList()

    fun require(key: ProviderKey): ExternalIdentityProvider =
        byKey[key] ?: throw ProviderException("unknown provider ${key.value}")
}
