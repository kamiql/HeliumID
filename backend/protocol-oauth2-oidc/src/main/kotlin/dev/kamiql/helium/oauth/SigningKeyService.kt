package dev.kamiql.helium.oauth

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.kamiql.helium.domain.common.SigningKeyId
import dev.kamiql.helium.domain.crypto.EncryptedSecret
import dev.kamiql.helium.domain.crypto.SecretCipher
import dev.kamiql.helium.domain.repository.SigningKeyRepository
import dev.kamiql.helium.domain.token.SigningAlgorithm
import dev.kamiql.helium.domain.token.SigningKey
import dev.kamiql.helium.domain.token.SigningKeyStatus
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Owns the token signing keys and the JWKS document.
 *
 * Rotation follows concept §7.2 exactly, and the ordering is the part that matters: a key is
 * **published before it is used**, and its public half stays published until every token it
 * signed has expired. Skipping either half breaks verifiers that cache JWKS — which is all of
 * them.
 *
 * Private keys are stored encrypted with the KMS-backed [SecretCipher] and decrypted into a
 * short-lived cache; they are never logged and never leave the process.
 */
class SigningKeyService(
    private val repository: SigningKeyRepository,
    private val cipher: SecretCipher,
    /** How long a retired key stays in JWKS. Must exceed the longest token lifetime. */
    private val overlapPeriod: Duration = Duration.ofHours(24),
) {

    private val log = LoggerFactory.getLogger(SigningKeyService::class.java)

    /**
     * Decrypted private keys, keyed by `kid`.
     *
     * Signing happens on every token request, so decrypting per call would put a KMS round
     * trip on the hot path. Entries are immutable — a key's material never changes, only its
     * status — so the cache cannot go stale in a way that matters.
     */
    private val privateKeyCache = java.util.concurrent.ConcurrentHashMap<String, ECKey>()

    /**
     * Returns the key to sign with, creating the very first one if the table is empty.
     *
     * Bootstrapping here rather than in a migration keeps private key material out of SQL
     * files and lets the key be generated with the deployment's own cipher configuration.
     */
    suspend fun activeSigningKey(now: Instant): LoadedSigningKey {
        val existing = repository.findActive()
        if (existing != null) return load(existing)

        log.info("no active signing key found; generating the initial key")
        val generated = generate(now)
        repository.promote(generated.id, now)
        return load(generated.copy(status = SigningKeyStatus.ACTIVE, activatedAt = now))
    }

    /**
     * Generates a new key in `PENDING` state.
     *
     * Deliberately does not promote it: publish first, sign later. Call [promote] once
     * verifiers have had time to refresh their JWKS cache.
     */
    suspend fun generate(now: Instant): SigningKey {
        val kid = SigningKeyId("auth-signing-key-${KID_FORMAT.format(now)}-${now.epochSecond}")
        val ecKey = ECKeyGenerator(Curve.P_256)
            .keyID(kid.value)
            .generate()

        val encrypted = cipher.encrypt(ecKey.toJSONString().toByteArray(StandardCharsets.UTF_8))
        val key = SigningKey(
            id = kid,
            algorithm = SigningAlgorithm.ES256,
            publicJwk = ecKey.toPublicJWK().toJSONString(),
            encryptedPrivateKey = encrypted.encode(),
            status = SigningKeyStatus.PENDING,
            createdAt = now,
            activatedAt = null,
            retiresAt = null,
        )
        return repository.insert(key)
    }

    /** Makes [id] the signer and demotes the previous one to `RETIRING`. */
    suspend fun promote(id: SigningKeyId, now: Instant) {
        repository.promote(id, now)
        log.info("signing key {} promoted", id)
    }

    /**
     * Retires keys whose overlap window has elapsed.
     *
     * Run by the `jobs` module. Retiring too early invalidates live tokens; never retiring
     * grows JWKS without bound and keeps compromised keys trusted.
     */
    suspend fun retireExpired(now: Instant): Int {
        val cutoff = now.minus(overlapPeriod)
        val retired = repository.listPublishable()
            .filter { it.status == SigningKeyStatus.RETIRING }
            .filter { key -> (key.activatedAt ?: key.createdAt).isBefore(cutoff) }
        retired.forEach {
            repository.retire(it.id, now)
            privateKeyCache.remove(it.id.value)
        }
        if (retired.isNotEmpty()) log.info("retired {} signing key(s)", retired.size)
        return retired.size
    }

    /**
     * The JWKS document served at `/.well-known/jwks.json`.
     *
     * Contains every non-retired key: the current signer, anything still in its overlap window,
     * and anything published but not yet signing.
     */
    suspend fun jwks(): String {
        val keys = repository.listPublishable().joinToString(",") { it.publicJwk }
        return """{"keys":[$keys]}"""
    }

    /** Resolves a `kid` for verification. Returns `null` for unknown or retired keys. */
    suspend fun verificationKey(kid: String): ECKey? {
        val stored = repository.findById(SigningKeyId(kid))?.takeIf { it.isPublishable } ?: return null
        return runCatching { JWK.parse(stored.publicJwk).toECKey() }.getOrNull()
    }

    private fun load(key: SigningKey): LoadedSigningKey {
        val ecKey = privateKeyCache.computeIfAbsent(key.id.value) {
            val encrypted = EncryptedSecret.decode(key.encryptedPrivateKey)
                // Fail closed (§7.6): an unreadable signing key must stop token issuance, not
                // silently fall back to an older one.
                ?: error("signing key ${key.id} has malformed encrypted material")
            val json = String(cipher.decrypt(encrypted), StandardCharsets.UTF_8)
            ECKey.parse(json)
        }
        return LoadedSigningKey(key.id, key.algorithm, ecKey)
    }

    private companion object {
        val KID_FORMAT: DateTimeFormatter =
            DateTimeFormatter.ofPattern("yyyy-MM").withZone(ZoneOffset.UTC)
    }
}

/** A signing key with its private half decrypted and ready to use. */
class LoadedSigningKey(
    val id: SigningKeyId,
    val algorithm: SigningAlgorithm,
    val key: ECKey,
) {
    override fun toString(): String = "LoadedSigningKey(${id.value}, ${algorithm.joseName})"
}
