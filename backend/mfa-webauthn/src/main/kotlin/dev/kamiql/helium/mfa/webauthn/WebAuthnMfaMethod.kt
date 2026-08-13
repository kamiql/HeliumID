package dev.kamiql.helium.mfa.webauthn

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.AttestedCredentialDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.util.Base64UrlUtil
import com.webauthn4j.verifier.CoreMaliciousCounterValueHandler
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaResponse
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.MfaVerificationResult
import dev.kamiql.helium.domain.mfa.UserVerificationRequirement
import dev.kamiql.helium.domain.mfa.WebAuthnAuthenticationOptions
import dev.kamiql.helium.domain.mfa.WebAuthnCredential
import dev.kamiql.helium.domain.mfa.WebAuthnRegistrationOptions
import dev.kamiql.helium.domain.mfa.WebAuthnRelyingParty
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.repository.WebAuthnCredentialRepository
import dev.kamiql.helium.flow.port.SecurityTransactionStore
import dev.kamiql.helium.spi.EnrollmentChallenge
import dev.kamiql.helium.spi.MfaMethod
import dev.kamiql.helium.spi.VerificationChallenge
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.time.Instant

/**
 * WebAuthn / passkey second factor.
 *
 * The ceremony itself — CBOR decoding, COSE key handling, signature verification — comes from
 * webauthn4j. This class owns the parts the library deliberately leaves to the relying party,
 * and those parts are where the security actually lives:
 *
 *  * **The challenge is server-chosen and single-use.** It is written to
 *    [SecurityTransactionStore] on `begin*` and consumed with `take` — never `peek` — so a
 *    captured assertion cannot be replayed. Redemption happens before any parsing, so a
 *    malformed response spends the challenge too and an attacker gets one attempt, not many.
 *  * **Registration and authentication challenges live under different kinds.** Sharing one
 *    kind would let a challenge issued for `navigator.credentials.create()` be answered with an
 *    assertion, which is a login without a login.
 *  * **Origin and RP ID are the whole phishing-resistance story.** [WebAuthnRelyingParty] is the
 *    only source of allowed origins; nothing here derives one from the request.
 *  * **The signature counter is a cloned-authenticator signal**, applied through a conditional
 *    UPDATE rather than an in-memory comparison — see [applyCounterPolicy].
 *
 * Nothing in this class logs credential ids, public keys, challenges, client data or raw
 * authenticator output. A rejection is reported by identifier only.
 */
class WebAuthnMfaMethod(
    private val mfaRepository: MfaRepository,
    private val credentials: WebAuthnCredentialRepository,
    private val users: UserRepository,
    private val transactions: SecurityTransactionStore,
    private val random: RandomSource,
    private val relyingParty: WebAuthnRelyingParty,
) : MfaMethod {

    private val log = LoggerFactory.getLogger(WebAuthnMfaMethod::class.java)

    private val objectConverter = ObjectConverter()
    private val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)

    /**
     * Non-strict because this server does not do attestation.
     *
     * The strict manager walks the attestation statement to a trust anchor, which answers "is
     * this really a YubiKey model X". For a second factor that question is not worth asking: we
     * do not maintain an authenticator allow-list, so a verdict we would ignore is only a source
     * of enrollment failures for perfectly good platform authenticators. What we give up is the
     * ability to tell a genuine hardware key from a software one; what we keep — and what the
     * factor rests on — is the signature check, the challenge, the origin and the RP ID hash,
     * none of which attestation contributes to.
     *
     * If an operator ever needs device attestation, that is a policy change with an authenticator
     * allow-list behind it, not a flag flip here.
     */
    private val manager: WebAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter).apply {
        // webauthn4j's default handler throws on a non-advancing counter. Silence it so the
        // decision is made in exactly one place: the repository's conditional UPDATE, which is
        // atomic across concurrent assertions where an in-memory comparison is not. See
        // [applyCounterPolicy] for the policy this replaces it with.
        authenticationDataVerifier.maliciousCounterValueHandler = CoreMaliciousCounterValueHandler { }
    }

    private val supportedAlgorithms: List<PublicKeyCredentialParameters> =
        WebAuthnRegistrationOptions.DEFAULT_ALGORITHMS.map {
            PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(it))
        }

    private val allowedOrigins: Set<Origin> = relyingParty.origins.map { Origin.create(it) }.toSet()

    override val type: MfaType = MfaType.WEBAUTHN

    override suspend fun beginEnrollment(userId: UserId, now: Instant): EnrollmentChallenge {
        val user = users.findById(userId) ?: error("cannot enroll a passkey for unknown user")

        // Any pending enrollment is discarded, for the same reason TOTP does it: restarting
        // setup must not leave a second, half-registered factor behind that could later be
        // activated by an attacker who intercepted the earlier ceremony.
        mfaRepository.listFactors(userId)
            .filter { it.type == MfaType.WEBAUTHN && it.status == MfaFactorStatus.PENDING }
            .forEach { mfaRepository.revokeFactor(it.id, now) }

        val factor = MfaFactor(
            id = MfaFactorId.random(),
            userId = userId,
            type = MfaType.WEBAUTHN,
            label = "Passkey",
            // PENDING until the authenticator produces an attestation we can verify.
            status = MfaFactorStatus.PENDING,
            createdAt = now,
            lastUsedAt = null,
        )
        mfaRepository.insertFactor(factor)

        val challenge = newChallenge()
        transactions.put(
            id = registrationTransaction(factor.id),
            kind = REGISTRATION_CHALLENGE_KIND,
            payload = challenge,
            ttl = WebAuthnCredential.CHALLENGE_LIFETIME,
        )

        return EnrollmentChallenge.WebAuthn(
            factorId = factor.id,
            options = WebAuthnRegistrationOptions(
                challenge = challenge,
                rpId = relyingParty.id,
                rpName = relyingParty.name,
                // The opaque user id, never the email or username: it is written to the
                // authenticator, may be shown by the platform's account picker, and has to
                // survive a rename.
                userHandle = Base64UrlUtil.encodeToString(userId.toBytes()),
                userName = user.primaryEmail.display,
                userDisplayName = user.displayName,
                algorithms = WebAuthnRegistrationOptions.DEFAULT_ALGORITHMS,
                // Deliberately *every* credential, including those whose factor is revoked or
                // still pending — the opposite of the filter [beginVerification] applies.
                // Revoking a factor leaves the credential row in place, and this is the list that
                // makes that useful: an authenticator whose passkey was removed must refuse to
                // enroll itself again rather than quietly minting a second one the user cannot
                // tell apart from the one they just deleted.
                excludeCredentialIds = credentials.listForUser(userId)
                    .map { Base64UrlUtil.encodeToString(it.credentialId) },
                userVerification = UserVerificationRequirement.PREFERRED,
                timeout = WebAuthnCredential.CHALLENGE_LIFETIME,
            ),
        )
    }

    override suspend fun confirmEnrollment(
        factorId: MfaFactorId,
        response: MfaResponse,
        now: Instant,
    ): Boolean {
        // A response of any other shape is a client sending the wrong ceremony's output here.
        // Treated as a plain failure so it cannot be used to tell the two ceremonies apart.
        val registration = response as? MfaResponse.WebAuthnRegistration ?: return false

        val factor = mfaRepository.findFactor(factorId) ?: return false
        if (factor.type != MfaType.WEBAUTHN || factor.status != MfaFactorStatus.PENDING) return false

        // Single-use, and spent before anything is parsed: a client that fails verification has
        // to ask for a new challenge rather than grinding against this one.
        val challenge = transactions.take(registrationTransaction(factorId), REGISTRATION_CHALLENGE_KIND)
            ?: return false

        val attestationObject = decodeBase64Url(registration.attestationObject) ?: return false
        val clientDataJson = decodeBase64Url(registration.clientDataJson) ?: return false

        val data = runCatching {
            manager.verify(
                RegistrationRequest(attestationObject, clientDataJson, registration.transports.toSet()),
                RegistrationParameters(
                    serverProperty(challenge),
                    supportedAlgorithms,
                    // PREFERRED user verification: the password already established who is
                    // signing in, and demanding a PIN on top only locks out security keys that
                    // cannot do it. User *presence* stays mandatory.
                    /* userVerificationRequired = */ false,
                    /* userPresenceRequired = */ true,
                ),
            )
        }.getOrElse { failure ->
            log.info("passkey registration rejected for factor {}: {}", factorId, failure.javaClass.simpleName)
            return false
        }

        val authenticatorData = data.attestationObject?.authenticatorData ?: return false
        val attested = authenticatorData.attestedCredentialData ?: return false

        // The authoritative credential id is the attested one. Cross-checking it against what
        // the client claimed stops a response being filed under an id the signature does not
        // cover, which would otherwise leave a credential that can never be matched again — or,
        // worse, one that shadows another entry.
        val claimedCredentialId = decodeBase64Url(registration.credentialId) ?: return false
        if (!claimedCredentialId.contentEquals(attested.credentialId)) {
            log.warn("passkey registration for factor {} claimed a credential id the attestation does not cover", factorId)
            return false
        }

        credentials.insert(
            WebAuthnCredential(
                factorId = factorId,
                userId = factor.userId,
                credentialId = attested.credentialId,
                // Attested credential data, not a bare COSE key: it carries the AAGUID and the
                // credential id alongside the key, so one blob round-trips the whole record.
                publicKey = attestedCredentialDataConverter.convert(attested),
                signatureCounter = authenticatorData.signCount,
                aaguid = attested.aaguid.takeIf { it != AAGUID.ZERO }?.value,
                transports = registration.transports.joinToString(","),
                // An authenticator that verified the user at registration is expected to keep
                // doing so; one that never can is not suddenly asked to. Recording what actually
                // happened avoids both a downgrade and a lockout.
                userVerifiedRequired = authenticatorData.isFlagUV,
                backupEligible = authenticatorData.isFlagBE,
                backupState = authenticatorData.isFlagBS,
                rpId = relyingParty.id,
                createdAt = now,
                lastUsedAt = null,
            ),
        )

        mfaRepository.activateFactor(factorId, now)
        return true
    }

    override suspend fun beginVerification(userId: UserId, now: Instant): VerificationChallenge? {
        mfaRepository.findActiveFactorOfType(userId, MfaType.WEBAUTHN) ?: return null

        // Revoking a factor is a status update; the credential row outlives it. So membership in
        // `allowCredentials` has to be decided by the factor, not by the credential table —
        // otherwise a passkey the user deleted is still offered, which both invites a ceremony
        // that [verify] will refuse and tells anyone watching that the credential once existed.
        val activeFactorIds = mfaRepository.listFactors(userId)
            .filter { it.type == MfaType.WEBAUTHN && it.isActive }
            .mapTo(mutableSetOf()) { it.id }

        val challenge = newChallenge()
        transactions.put(
            id = authenticationTransaction(userId),
            kind = AUTHENTICATION_CHALLENGE_KIND,
            payload = challenge,
            ttl = WebAuthnCredential.CHALLENGE_LIFETIME,
        )

        return VerificationChallenge.WebAuthn(
            options = WebAuthnAuthenticationOptions(
                challenge = challenge,
                rpId = relyingParty.id,
                // Named rather than discovered: this is a *second* factor, so the user is already
                // identified and a non-discoverable security key needs to be told which credential
                // to use. Credentials registered under a previous rpId are left out for the same
                // reason as revoked ones — they cannot pass verification, so offering them only
                // produces a dead end.
                allowCredentialIds = credentials.listForUser(userId)
                    .filter { it.factorId in activeFactorIds && it.rpId == relyingParty.id }
                    .map { Base64UrlUtil.encodeToString(it.credentialId) },
                userVerification = UserVerificationRequirement.PREFERRED,
                timeout = WebAuthnCredential.CHALLENGE_LIFETIME,
            ),
        )
    }

    override suspend fun verify(userId: UserId, response: MfaResponse, now: Instant): MfaVerificationResult {
        val assertion = response as? MfaResponse.WebAuthnAssertion ?: return MfaVerificationResult.Rejected

        // Spent first, for the same reason as in enrollment. A missing entry means the challenge
        // expired or was already redeemed; both are reported as Expired so the client restarts
        // the ceremony instead of retrying a challenge that will never succeed.
        val challenge = transactions.take(authenticationTransaction(userId), AUTHENTICATION_CHALLENGE_KIND)
            ?: return MfaVerificationResult.Expired

        val credentialId = decodeBase64Url(assertion.credentialId) ?: return MfaVerificationResult.Rejected

        // Scoped to the user. A global lookup would let an assertion collected for one account be
        // presented against another.
        val credential = credentials.findByCredentialId(userId, credentialId)
            ?: return MfaVerificationResult.Rejected

        // A credential registered under a different relying-party id belongs to a domain this
        // server no longer is. Failing loudly beats silently accepting a signature scoped
        // somewhere else.
        if (credential.rpId != relyingParty.id) {
            log.warn("rejected a passkey registered under a stale relying-party id for factor {}", credential.factorId)
            return MfaVerificationResult.Rejected
        }

        // The authority on whether this passkey may still be used is the *factor*, not the
        // credential row: revocation flips the factor's status and leaves the credential in place
        // (deliberately — see the exclude list in [beginEnrollment]). Skipping this check would
        // mean a passkey the user removed still logs them in. Rejected exactly like a bad
        // signature, so a revoked credential is indistinguishable from an unknown one.
        val factor = mfaRepository.findFactor(credential.factorId) ?: return MfaVerificationResult.Rejected
        if (factor.type != MfaType.WEBAUTHN || !factor.isActive || factor.userId != userId) {
            return MfaVerificationResult.Rejected
        }

        // Present only for a discoverable credential, which a second factor normally is not.
        // When it is there it must name this user — WebAuthn L3 §7.2 step 6.
        val userHandle = assertion.userHandle?.let { decodeBase64Url(it) ?: return MfaVerificationResult.Rejected }
        if (userHandle != null && !userHandle.contentEquals(userId.toBytes())) {
            log.warn("rejected an assertion whose user handle does not match the authenticating user")
            return MfaVerificationResult.Rejected
        }

        val authenticatorData = decodeBase64Url(assertion.authenticatorData) ?: return MfaVerificationResult.Rejected
        val clientDataJson = decodeBase64Url(assertion.clientDataJson) ?: return MfaVerificationResult.Rejected
        val signature = decodeBase64Url(assertion.signature) ?: return MfaVerificationResult.Rejected

        val data = runCatching {
            manager.verify(
                AuthenticationRequest(credentialId, userHandle, authenticatorData, clientDataJson, signature),
                AuthenticationParameters(
                    serverProperty(challenge),
                    credentialRecord(credential),
                    listOf(credential.credentialId),
                    // Not `credential.userVerifiedRequired`. We advertise PREFERRED, which lets
                    // the authenticator decide per ceremony, so demanding user verification here
                    // would enforce something we never asked for and lock out a key that did a
                    // PIN at enrollment and declines to at login. The stored flag records what
                    // the authenticator actually did, for audit; making it a gate means changing
                    // the advertised `userVerification` to REQUIRED in the same commit.
                    /* userVerificationRequired = */ false,
                    /* userPresenceRequired = */ true,
                ),
            )
        }.getOrElse { failure ->
            log.info(
                "passkey assertion rejected for factor {}: {}",
                credential.factorId,
                failure.javaClass.simpleName,
            )
            return MfaVerificationResult.Rejected
        }

        if (!applyCounterPolicy(credential, data.authenticatorData?.signCount ?: 0L, now)) {
            return MfaVerificationResult.Rejected
        }

        mfaRepository.touchFactor(factor.id, now)
        // No step to record: replay is prevented by the single-use challenge, not by a counter of
        // consumed time windows the way TOTP does it.
        return MfaVerificationResult.Verified(factor.id, acceptedStep = null)
    }

    override suspend fun isEnrolled(userId: UserId): Boolean =
        mfaRepository.findActiveFactorOfType(userId, MfaType.WEBAUTHN) != null

    /**
     * Applies the signature-counter policy (WebAuthn L3 §7.2 step 22).
     *
     * When the stored counter and the presented one are both zero the check is skipped outright,
     * because the spec says so: a large share of authenticators — every synced passkey among
     * them — never keep a counter, and demanding an advance from them would reject every
     * legitimate login.
     *
     * Otherwise the counter must strictly advance, and it advances through a conditional UPDATE
     * rather than a comparison here. Two assertions racing with the same counter would both pass
     * an in-memory check; only one can win the UPDATE.
     *
     * @return `false` when the counter failed to advance, which is the cloned-authenticator
     *         signal. Not proof — a malfunctioning authenticator looks the same — but the
     *         conservative reading is the right one for a second factor.
     */
    private suspend fun applyCounterPolicy(
        credential: WebAuthnCredential,
        presentedCounter: Long,
        now: Instant,
    ): Boolean {
        if (presentedCounter == 0L && credential.signatureCounter == 0L) {
            credentials.touch(credential.factorId, now)
            return true
        }

        if (!credentials.tryAdvanceSignatureCounter(credential.factorId, presentedCounter, now)) {
            // Identifiers only. The counter values themselves are authenticator state and stay
            // out of the log line.
            log.warn(
                "passkey signature counter failed to advance for factor {}; possible cloned authenticator",
                credential.factorId,
            )
            return false
        }
        return true
    }

    /**
     * Rebuilds the webauthn4j view of a stored credential.
     *
     * The backup flags are passed back in on purpose: webauthn4j compares them against the
     * assertion and rejects a credential that changed its backup eligibility, which a genuine
     * authenticator never does. Transports are left out — they are advisory client hints and
     * play no part in verification.
     */
    private fun credentialRecord(credential: WebAuthnCredential) =
        CredentialRecordImpl(
            /* attestationStatement = */ null,
            /* uvInitialized = */ credential.userVerifiedRequired,
            /* backupEligible = */ credential.backupEligible,
            /* backupState = */ credential.backupState,
            /* counter = */ credential.signatureCounter,
            /* attestedCredentialData = */ attestedCredentialDataConverter.convert(credential.publicKey),
            /* authenticatorExtensions = */ null,
            /* clientData = */ null,
            /* clientExtensions = */ null,
            /* transports = */ null,
        )

    /**
     * The origins and RP ID an assertion is checked against.
     *
     * Built from [relyingParty] every time and never from anything in the request — an origin
     * derived from a header is an origin the caller chooses, which is exactly the attack passkeys
     * are supposed to be immune to.
     */
    private fun serverProperty(challenge: String): ServerProperty =
        ServerProperty.builder()
            .origins(allowedOrigins)
            .rpId(relyingParty.id)
            .challenge(DefaultChallenge(Base64UrlUtil.decode(challenge)))
            .build()

    private fun newChallenge(): String =
        Base64UrlUtil.encodeToString(random.bytes(WebAuthnCredential.CHALLENGE_BYTES))

    /** Client-supplied base64url. Malformed input is a failed attempt, not an exception. */
    private fun decodeBase64Url(value: String): ByteArray? =
        runCatching { Base64UrlUtil.decode(value) }.getOrNull()

    private fun registrationTransaction(factorId: MfaFactorId) =
        TransactionId("webauthn-registration:$factorId")

    /**
     * Keyed by the user so [verify] can find the challenge from the arguments the SPI gives it.
     *
     * The accepted consequence: two concurrent logins for the same account overwrite each other's
     * challenge and the last one wins, leaving the other to restart the ceremony. That is a
     * usability cost in a rare case, and the alternative — handing the client a transaction id to
     * pass back — would mean widening [MfaMethod.verify] for every method to serve one. Nothing
     * about it is exploitable: a challenge only ever gets *shorter*-lived, never reusable.
     */
    private fun authenticationTransaction(userId: UserId) =
        TransactionId("webauthn-authentication:$userId")

    private companion object {

        /**
         * Kept distinct so a registration challenge cannot be redeemed as a login assertion.
         *
         * A shared kind would mean a user part-way through enrolling a passkey is holding a
         * challenge that answers a login — a step-up satisfied by the enrollment the step-up was
         * supposed to protect.
         *
         * Declared here rather than imported from the Redis adapter: this module must not depend
         * on persistence, and the store takes the kind as a plain string precisely so it need not.
         */
        const val REGISTRATION_CHALLENGE_KIND = "webauthn_registration_challenge"
        const val AUTHENTICATION_CHALLENGE_KIND = "webauthn_authentication_challenge"
    }
}

/** The 16 raw bytes of the identifier, which is what an authenticator stores as the user handle. */
private fun UserId.toBytes(): ByteArray =
    ByteBuffer.allocate(16)
        .putLong(value.mostSignificantBits)
        .putLong(value.leastSignificantBits)
        .array()
