package dev.kamiql.helium.domain.token

import dev.kamiql.helium.domain.common.SigningKeyId
import java.time.Instant

/**
 * An asymmetric key pair used to sign access and ID tokens.
 *
 * Rotation follows concept §7.2: generate, publish the public half in JWKS, start signing with
 * it, keep the previous public half until every token it signed has expired, then retire.
 * Because verifiers cache JWKS, a key must be *published* well before it is *used*.
 */
data class SigningKey(
    val id: SigningKeyId,
    val algorithm: SigningAlgorithm,
    /** JWK serialization of the public key. Safe to publish; this is the whole point. */
    val publicJwk: String,
    /**
     * Encrypted private key material, in the [dev.kamiql.helium.domain.crypto.EncryptedSecret]
     * storage form. Never leaves the process in plaintext and is never logged.
     */
    val encryptedPrivateKey: String,
    val status: SigningKeyStatus,
    val createdAt: Instant,
    /** When this key started signing. `null` while it is published but not yet active. */
    val activatedAt: Instant?,
    /** After this instant the public half may be dropped from JWKS. */
    val retiresAt: Instant?,
) {
    val isPublishable: Boolean get() = status != SigningKeyStatus.RETIRED
    val isSigning: Boolean get() = status == SigningKeyStatus.ACTIVE
}

enum class SigningKeyStatus {
    /** In JWKS, not signing yet. Gives verifiers time to refresh their cache. */
    PENDING,

    /** The one key currently used for signing. Exactly one key is ACTIVE at a time. */
    ACTIVE,

    /** No longer signing; still in JWKS so previously issued tokens still verify. */
    RETIRING,

    /** Removed from JWKS. Kept in the table for forensics only. */
    RETIRED,
}

/**
 * Concept §4.2 prefers EdDSA or ES256; RSA only where an ecosystem demands it.
 *
 * @param joseName the `alg` value published in JWKS and used in the JWS header.
 */
enum class SigningAlgorithm(val joseName: String) {
    ES256("ES256"),
    EDDSA("EdDSA"),
    RS256("RS256"),
    ;

    companion object {
        val DEFAULT: SigningAlgorithm = ES256
    }
}
