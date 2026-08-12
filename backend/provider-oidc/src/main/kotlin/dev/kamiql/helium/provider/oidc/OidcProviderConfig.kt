package dev.kamiql.helium.provider.oidc

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.identity.Issuer
import dev.kamiql.helium.domain.identity.ProviderKey
import java.net.InetAddress
import java.net.URI

/**
 * Static configuration for one external OIDC provider.
 *
 * Every endpoint is configured, never discovered from user input. Concept §4.9: "Do not allow
 * arbitrary provider URLs from client input" — a provider registry built from configuration is
 * the mitigation for SSRF, and it only works if nothing here can be influenced by a request.
 *
 * @param issuer the exact `iss` value that must appear in the ID token. This is the trust
 *        anchor: an ID token from any other issuer is rejected even if it is validly signed.
 * @param scopes provider scopes to request.
 */
data class OidcProviderConfig(
    val key: ProviderKey,
    val displayName: String,
    val issuer: Issuer,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val jwksUri: String,
    val userInfoEndpoint: String?,
    val clientId: String,
    val clientSecret: Secret,
    val scopes: Set<String> = setOf("openid", "email", "profile"),
    /** Only ever true for a local test provider. Production must use HTTPS. */
    val allowInsecureTransport: Boolean = false,
) {
    init {
        listOf(authorizationEndpoint, tokenEndpoint, jwksUri).forEach { endpoint ->
            require(allowInsecureTransport || endpoint.startsWith("https://")) {
                "provider ${key.value} endpoint must use https: $endpoint"
            }
        }
    }

    companion object {
        /**
         * Google's endpoints, hardcoded rather than fetched from the discovery document.
         *
         * Fetching discovery at startup is convenient but adds a boot-time network dependency
         * and a moving target; Google's endpoints have been stable for years. If you do fetch
         * discovery, validate that the returned `issuer` equals the configured one before
         * trusting anything else in the document (concept §4.9).
         */
        fun google(clientId: String, clientSecret: Secret): OidcProviderConfig = OidcProviderConfig(
            key = ProviderKey("google"),
            displayName = "Google",
            issuer = Issuer("https://accounts.google.com"),
            authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth",
            tokenEndpoint = "https://oauth2.googleapis.com/token",
            jwksUri = "https://www.googleapis.com/oauth2/v3/certs",
            userInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo",
            clientId = clientId,
            clientSecret = clientSecret,
        )
    }
}

/**
 * Blocks outbound requests to addresses that only make sense from inside the network.
 *
 * Concept §4.9 requires blocking private and link-local ranges and preventing DNS rebinding.
 * This is a defence in depth: with a configuration-only provider registry there is no attacker
 * input in the URL to begin with, but a misconfigured or compromised registry entry should
 * still not be able to reach the metadata service or an internal admin port.
 *
 * The real fix at scale is an egress proxy, which concept §4.9 also recommends; this guard
 * exists so a deployment without one is not defenceless.
 */
object EgressGuard {

    /**
     * @return `null` when the URL is acceptable, or a reason string when it must be refused.
     */
    fun reject(url: String, allowLoopback: Boolean = false): String? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return "malformed url"
        val scheme = uri.scheme?.lowercase()
        if (scheme != "https" && !(scheme == "http" && allowLoopback)) return "scheme not allowed"
        val host = uri.host ?: return "missing host"

        val addresses = runCatching { InetAddress.getAllByName(host) }.getOrNull()
            ?: return "host does not resolve"

        // Every resolved address must be acceptable. Checking only the first would let a
        // multi-record DNS response smuggle an internal address past the check.
        addresses.forEach { address ->
            if (address.isLoopbackAddress && !allowLoopback) return "loopback address"
            if (address.isAnyLocalAddress) return "wildcard address"
            if (address.isLinkLocalAddress) return "link-local address"
            if (address.isSiteLocalAddress && !allowLoopback) return "private address"
            if (address.isMulticastAddress) return "multicast address"
            // 169.254.169.254 and friends: the cloud metadata endpoints.
            if (address.hostAddress == "169.254.169.254") return "metadata address"
        }
        return null
    }
}
