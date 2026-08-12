package dev.kamiql.helium.domain.identity

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.ExternalIdentityId
import dev.kamiql.helium.domain.common.UserId
import java.time.Instant

/**
 * Registry key of a configured provider adapter, e.g. `google`, `github`, `discord`.
 *
 * This is **not** the trust anchor. Two deployments can both call a provider `google`; only
 * the [Issuer] proves who actually asserted the identity.
 */
@JvmInline
value class ProviderKey(val value: String) {
    override fun toString(): String = value

    init {
        require(value.isNotBlank() && value.all { it.isLetterOrDigit() || it == '-' || it == '_' }) {
            "provider key must be a non-blank slug"
        }
    }
}

/**
 * The identity provider's issuer identifier — for OIDC the `iss` claim, for a plain OAuth API
 * integration a constant the adapter defines (e.g. `https://github.com`).
 */
@JvmInline
value class Issuer(val value: String) {
    override fun toString(): String = value
}

/** The provider's stable, opaque identifier for the end user (`sub`). Never an email. */
@JvmInline
value class ProviderSubject(val value: String) {
    override fun toString(): String = value
}

/**
 * A link between a local account and an identity at an external provider.
 *
 * The uniqueness key is `(issuer, subject)` and nothing else. Concept §9.4: linking by email
 * is unsafe because provider emails may be unverified, reassigned, or attacker controlled.
 */
data class ExternalIdentity(
    val id: ExternalIdentityId,
    val userId: UserId,
    val providerKey: ProviderKey,
    val issuer: Issuer,
    val subject: ProviderSubject,
    /**
     * The email the provider asserted at link time. Stored for display and support only —
     * never used to find or match an account.
     */
    val providerEmail: EmailAddress?,
    val createdAt: Instant,
    val lastLoginAt: Instant?,
)

/**
 * Normalized profile returned by a provider adapter after a successful code exchange.
 *
 * Adapters translate their provider's shape into this; nothing provider specific may leak
 * past it (CLAUDE.md: "No new provider-specific logic leaks into domain flows").
 */
data class ExternalProfile(
    val providerKey: ProviderKey,
    val issuer: Issuer,
    val subject: ProviderSubject,
    val email: EmailAddress?,
    /**
     * Whether the **provider** claims to have verified the email. Treated as a hint for
     * display; it never authorizes a link on its own.
     */
    val emailVerified: Boolean,
    val displayName: String?,
    val username: String?,
    /**
     * Provider-specific extras, already reduced to primitive values by the adapter.
     *
     * Never store the raw provider response here: concept §7.5 forbids logging or persisting
     * full provider payloads, and they routinely contain tokens.
     */
    val attributes: Map<String, String> = emptyMap(),
)
