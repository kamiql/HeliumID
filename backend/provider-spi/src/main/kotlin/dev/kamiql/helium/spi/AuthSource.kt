package dev.kamiql.helium.spi

import dev.kamiql.helium.domain.identity.ProviderKey

/**
 * How a subject can prove who they are.
 *
 * Concept §1.3 is explicit that these must **not** collapse into a single "provider"
 * abstraction. An OAuth provider redirects a browser and returns a profile; a directory takes
 * a username and password and answers yes or no; a passkey is a local signature. Forcing all
 * three through one interface produces an interface whose methods are meaningless for two
 * thirds of its implementations.
 */
sealed interface AuthSource {

    /** Local Argon2id password credential. */
    data object LocalPassword : AuthSource

    /** WebAuthn/passkey. Reserved for a later milestone. */
    data object Passkey : AuthSource

    /** Directory bind through a [CredentialSource] — the LDAP shape. */
    data object Directory : AuthSource

    /** Authorization-code redirect to an external OAuth/OIDC provider. */
    data class ExternalOAuth(val provider: ProviderKey) : AuthSource
}
