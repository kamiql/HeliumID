package dev.kamiql.helium.spi

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.Secret

/**
 * A directory that can answer "are these credentials valid?".
 *
 * This is the **LDAP-shaped** port, and it is deliberately different from
 * [ExternalIdentityProvider]: there is no browser redirect, no authorization code and no
 * token — the server presents the credentials on the user's behalf and the directory answers.
 *
 * No adapter ships in this milestone; the port exists so that adding one is an adapter plus
 * configuration, with no change to any flow. Concept §9.5 and CLAUDE.md both require LDAP to
 * be an adapter rather than a special case in domain logic.
 *
 * ### Implementing an LDAP adapter
 *
 * ```kotlin
 * class LdapCredentialSource(private val config: LdapConfig) : CredentialSource {
 *     override val key = CredentialSourceKey("corp-ldap")
 *
 *     override suspend fun authenticate(identifier: String, secret: Secret) =
 *         withContext(Dispatchers.IO) {
 *             // 1. resolve the DN with a *service* account, never by string-concatenating
 *             //    user input into a filter — LDAP injection is the SQL injection of directories
 *             // 2. bind as that DN with the supplied secret
 *             // 3. read the group memberships you map to roles
 *             // 4. close the connection; never cache the credential
 *         }
 * }
 * ```
 *
 * Rules an implementation must follow:
 *
 *  * **Never store the directory password.** Concept §9.5 is explicit. Only the mapped local
 *    identity and authorization metadata are persisted.
 *  * Escape every value interpolated into a search filter (RFC 4515).
 *  * Require StartTLS or LDAPS and validate the certificate chain; an unauthenticated bind
 *    over plaintext hands every password to the network.
 *  * Set connect and read timeouts. A hung directory must degrade to
 *    [CredentialAuthenticationResult.Unavailable], not to a stuck request thread.
 *  * Return [CredentialAuthenticationResult.InvalidCredentials] for both "no such user" and
 *    "wrong password", so the adapter does not become an enumeration oracle.
 */
interface CredentialSource {

    val key: CredentialSourceKey

    /**
     * @param identifier already normalized by the caller.
     * @param secret the presented credential. Must not be logged, cached or persisted.
     */
    suspend fun authenticate(identifier: String, secret: Secret): CredentialAuthenticationResult
}

@JvmInline
value class CredentialSourceKey(val value: String) {
    override fun toString(): String = value
}

sealed interface CredentialAuthenticationResult {

    /**
     * @param groups raw directory groups. Mapping them onto local roles is a policy decision
     *        made outside the adapter, so the same directory can drive different role models
     *        in different deployments.
     */
    data class Authenticated(
        val subject: String,
        val email: EmailAddress?,
        val displayName: String?,
        val groups: Set<String> = emptySet(),
        val attributes: Map<String, String> = emptyMap(),
    ) : CredentialAuthenticationResult

    /** Wrong password *or* unknown user. The two are not distinguished, on purpose. */
    data object InvalidCredentials : CredentialAuthenticationResult

    /** The directory says the account exists but is disabled or locked out. */
    data object AccountDisabled : CredentialAuthenticationResult

    /**
     * The directory could not be reached.
     *
     * Distinct from [InvalidCredentials] so callers can answer `503` instead of teaching users
     * that their password stopped working whenever the directory has a bad day.
     */
    data class Unavailable(val reason: String) : CredentialAuthenticationResult
}
