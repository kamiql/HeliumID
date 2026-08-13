package dev.kamiql.helium.domain.mfa

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.UserId
import java.time.Duration
import java.time.Instant
import java.util.UUID

/**
 * A registered passkey.
 *
 * One row per authenticator, and [factorId] is deliberately the same identifier as the owning
 * `MfaFactor` — the same one-row-per-factor shape `TotpFactor` uses. That is what lets a
 * passkey be listed, labelled and revoked through the generic factor endpoints instead of
 * needing a parallel set of its own.
 *
 * Nothing here is secret. A passkey's private key never leaves the authenticator, so unlike a
 * TOTP secret there is nothing to encrypt: a full dump of this table lets an attacker *verify*
 * signatures, never produce them.
 *
 * @param publicKey the authenticator's attested credential data, serialized by the WebAuthn
 *        adapter. Opaque here on purpose — decoding it would drag a CBOR parser into the
 *        domain.
 * @param signatureCounter last counter the authenticator reported. A value that fails to
 *        advance is the cloned-authenticator signal (§4.7); see
 *        [WebAuthnCredentialRepository.tryAdvanceSignatureCounter][dev.kamiql.helium.domain.repository.WebAuthnCredentialRepository.tryAdvanceSignatureCounter].
 * @param backupEligible whether the credential may be synced to other devices. Recorded
 *        because a syncable passkey and a hardware-bound one are not the same assurance, and
 *        an operator auditing an account needs to be able to tell them apart.
 * @param rpId the relying-party id the credential was registered under. Stored so a later
 *        change of domain fails verification loudly instead of silently accepting credentials
 *        scoped to the old one.
 */
data class WebAuthnCredential(
    val factorId: MfaFactorId,
    val userId: UserId,
    val credentialId: ByteArray,
    val publicKey: ByteArray,
    val signatureCounter: Long,
    val aaguid: UUID?,
    val transports: String,
    val userVerifiedRequired: Boolean,
    val backupEligible: Boolean,
    val backupState: Boolean,
    val rpId: String,
    val createdAt: Instant,
    val lastUsedAt: Instant?,
) {
    // ByteArray in a data class needs structural equality written out, as in TotpFactor.
    override fun equals(other: Any?): Boolean =
        other is WebAuthnCredential &&
            factorId == other.factorId &&
            credentialId.contentEquals(other.credentialId) &&
            publicKey.contentEquals(other.publicKey)

    override fun hashCode(): Int =
        31 * (31 * factorId.hashCode() + credentialId.contentHashCode()) + publicKey.contentHashCode()

    companion object {
        /** Concept §4.7: challenges carry at least 128 bits, matching the WebAuthn L3 advice. */
        const val CHALLENGE_BYTES: Int = 32

        /**
         * How long a registration or authentication challenge stays redeemable.
         *
         * Short because the whole ceremony is a single user gesture. Long enough that a user
         * hunting for a security key in a drawer does not have to start over.
         */
        val CHALLENGE_LIFETIME: Duration = Duration.ofMinutes(2)
    }
}

/**
 * Whether the authenticator must prove *the user* was present, not merely that the key was.
 *
 * For a second factor [PREFERRED] is the right default: the password already established who
 * is signing in, so demanding a PIN or biometric on top buys little and locks out plain
 * security keys that cannot do it.
 */
enum class UserVerificationRequirement { REQUIRED, PREFERRED, DISCOURAGED }

/**
 * `PublicKeyCredentialCreationOptions`, reduced to what this server actually decides.
 *
 * Modelled rather than passed through as JSON so the policy — which algorithms, which
 * verification level, which credentials to exclude — is a typed decision in one place instead
 * of a document assembled at the HTTP edge.
 *
 * @param challenge base64url; single-use and stored server-side for exactly one redemption.
 * @param userHandle base64url of the opaque user identifier. Never the email or username: it
 *        is stored on the authenticator, may be displayed by the platform, and outlives any
 *        rename.
 * @param excludeCredentialIds base64url ids the user has already registered, so an
 *        authenticator refuses to enroll itself twice rather than creating a silent duplicate.
 */
data class WebAuthnRegistrationOptions(
    val challenge: String,
    val rpId: String,
    val rpName: String,
    val userHandle: String,
    val userName: String,
    val userDisplayName: String,
    val algorithms: List<Long>,
    val excludeCredentialIds: List<String>,
    val userVerification: UserVerificationRequirement,
    val timeout: Duration,
) {
    companion object {
        /**
         * COSE algorithm identifiers offered, in order of preference.
         *
         * ES256 first because every platform authenticator supports it; RS256 last for older
         * hardware keys. EdDSA is offered ahead of RSA where available.
         */
        val DEFAULT_ALGORITHMS: List<Long> = listOf(-7L, -8L, -257L)
    }
}

/**
 * `PublicKeyCredentialRequestOptions`, reduced the same way.
 *
 * @param allowCredentialIds base64url ids of this user's registered passkeys. Populated
 *        because this is a *second* factor — the user is already identified, so there is no
 *        reason to ask the authenticator to discover a credential, and naming them keeps
 *        non-discoverable security keys working.
 */
data class WebAuthnAuthenticationOptions(
    val challenge: String,
    val rpId: String,
    val allowCredentialIds: List<String>,
    val userVerification: UserVerificationRequirement,
    val timeout: Duration,
)

/**
 * Relying-party identity and the origins allowed to produce assertions for it.
 *
 * This is the control that makes passkeys phishing-resistant, so it is a typed, validated
 * config object rather than a pair of loose strings. [rpId] must be a registrable suffix of
 * every origin in [origins]; a value that is too broad — a domain whose subdomains are handed
 * to third parties — hands those third parties the ability to mint assertions for this server.
 */
data class WebAuthnRelyingParty(
    val id: String,
    val name: String,
    val origins: Set<String>,
) {
    init {
        require(id.isNotBlank()) { "webauthn relying-party id must not be blank" }
        require(origins.isNotEmpty()) { "webauthn requires at least one allowed origin" }
    }
}
