package dev.kamiql.helium.domain.client

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.ConsentId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.UserId
import java.time.Instant

/**
 * A registered relying party.
 *
 * Everything the authorization endpoint needs to make a security decision lives here; nothing
 * is inferred from the request. An unregistered value is a rejection, never a default.
 */
data class OAuthClient(
    val clientId: ClientId,
    val name: String,
    val type: ClientType,
    /** `null` for public clients. Confidential clients store only a hash. */
    val secretHash: String?,
    val secretRotatedAt: Instant?,
    /** Exact-match allowlist. Prefix and wildcard matching are not supported, by design. */
    val redirectUris: Set<String>,
    val allowedScopes: Set<String>,
    val allowedGrantTypes: Set<GrantType>,
    /** Skips the consent screen. Only ever true for first-party clients you operate. */
    val skipConsent: Boolean,
    /** Audience values placed in access tokens issued to this client. */
    val audiences: Set<String>,
    val enabled: Boolean,
    val createdAt: Instant,
    val updatedAt: Instant,
) {
    val isConfidential: Boolean get() = type == ClientType.CONFIDENTIAL

    /**
     * Exact string comparison against the registered set.
     *
     * Concept §4.9 and §5.1: "Use exact redirect URI matching." Any normalization here —
     * trailing slashes, case folding the path, ignoring the query — reopens the open-redirect
     * hole this check exists to close.
     */
    fun allowsRedirectUri(candidate: String): Boolean = candidate in redirectUris

    /** Returns the scopes this client may not request, or an empty set when all are allowed. */
    fun rejectedScopes(requested: Set<String>): Set<String> = requested - allowedScopes
}

enum class ClientType {
    /** SPA or native app. No secret; PKCE is mandatory. */
    PUBLIC,

    /** Server-side app that can keep a secret. */
    CONFIDENTIAL,
}

enum class GrantType(val wireValue: String) {
    AUTHORIZATION_CODE("authorization_code"),
    REFRESH_TOKEN("refresh_token"),
    CLIENT_CREDENTIALS("client_credentials"),
    ;

    companion object {
        fun parse(raw: String): GrantType? = entries.firstOrNull { it.wireValue == raw }

        /**
         * `password` is absent from this enum on purpose and must stay absent.
         * CLAUDE.md: "Never add the password grant."
         */
        val FORBIDDEN_WIRE_VALUES: Set<String> = setOf("password", "implicit")
    }
}

/**
 * A newly registered client with its one-and-only look at the generated secret.
 *
 * The plaintext is never stored and cannot be recovered — rotation issues a new one.
 */
class RegisteredClient(
    val client: OAuthClient,
    private val plaintextSecret: String?,
) {
    /** `null` for public clients. Display once, then discard. */
    fun secret(): Secret? = plaintextSecret?.let(Secret::of)

    override fun toString(): String = "RegisteredClient(${client.clientId}, secret=redacted)"
}

/** A scope the authorization server knows about. */
data class Scope(
    val name: String,
    /** Sentence shown on the consent screen. Must be understandable by a non-technical user. */
    val description: String,
    /** Granted without appearing on the consent screen (`openid`). */
    val implicit: Boolean = false,
) {
    companion object {
        const val OPENID: String = "openid"
        const val PROFILE: String = "profile"
        const val EMAIL: String = "email"
        const val OFFLINE_ACCESS: String = "offline_access"

        /** Scopes every deployment understands; more are registered per client. */
        val STANDARD: List<Scope> = listOf(
            Scope(OPENID, "Confirm your identity", implicit = true),
            Scope(PROFILE, "See your name and username"),
            Scope(EMAIL, "See your email address"),
            Scope(OFFLINE_ACCESS, "Stay signed in when you are not using the app"),
        )
    }
}

/**
 * A user's standing approval of a set of scopes for one client.
 *
 * Narrowing the granted set never requires re-consent; widening it always does.
 */
data class Consent(
    val id: ConsentId,
    val userId: UserId,
    val clientId: ClientId,
    val grantedScopes: Set<String>,
    val grantedAt: Instant,
    val revokedAt: Instant?,
) {
    fun covers(requested: Set<String>): Boolean = revokedAt == null && grantedScopes.containsAll(requested)
}
