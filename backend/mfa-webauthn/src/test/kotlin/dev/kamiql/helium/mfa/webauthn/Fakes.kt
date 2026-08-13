package dev.kamiql.helium.mfa.webauthn

import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.RecoveryCode
import dev.kamiql.helium.domain.mfa.TotpFactor
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.WebAuthnCredential
import dev.kamiql.helium.domain.repository.MfaRepository
import dev.kamiql.helium.domain.repository.WebAuthnCredentialRepository
import dev.kamiql.helium.flow.port.SecurityTransactionStore
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64

/**
 * In-memory doubles for the ports the adapter drives.
 *
 * Fakes rather than mocks because every one of these tests turns on *state* — a challenge that
 * was consumed, a counter that did or did not move, a factor that was revoked. Stubbed
 * per-call answers would let a test pass while the adapter did the wrong thing between calls.
 *
 * The behaviour that matters is copied faithfully from the port contracts: [take] is atomic
 * read-and-delete, and [tryAdvanceSignatureCounter] is a conditional update that only accepts a
 * strictly greater value.
 */
class FakeTransactionStore : SecurityTransactionStore {

    private val entries = mutableMapOf<Pair<String, String>, String>()

    /** Every kind ever written, so a test can prove registration and login do not share one. */
    val kindsWritten = mutableSetOf<String>()

    override suspend fun put(id: TransactionId, kind: String, payload: String, ttl: Duration) {
        entries[id.value to kind] = payload
        kindsWritten += kind
    }

    override suspend fun peek(id: TransactionId, kind: String): String? = entries[id.value to kind]

    override suspend fun take(id: TransactionId, kind: String): String? = entries.remove(id.value to kind)

    override suspend fun delete(id: TransactionId, kind: String) {
        entries.remove(id.value to kind)
    }

    override suspend fun increment(id: TransactionId, kind: String, ttl: Duration): Long =
        error("not used by the WebAuthn adapter")

    fun isEmpty(): Boolean = entries.isEmpty()
}

class FakeMfaRepository : MfaRepository {

    private val factors = linkedMapOf<MfaFactorId, MfaFactor>()

    override suspend fun listFactors(userId: UserId): List<MfaFactor> =
        factors.values.filter { it.userId == userId }

    override suspend fun findFactor(id: MfaFactorId): MfaFactor? = factors[id]

    override suspend fun findActiveFactorOfType(userId: UserId, type: MfaType): MfaFactor? =
        factors.values.firstOrNull { it.userId == userId && it.type == type && it.isActive }

    override suspend fun insertFactor(factor: MfaFactor): MfaFactor {
        factors[factor.id] = factor
        return factor
    }

    override suspend fun activateFactor(id: MfaFactorId, at: Instant) {
        factors.computeIfPresent(id) { _, f -> f.copy(status = MfaFactorStatus.ACTIVE) }
    }

    override suspend fun relabelFactor(id: MfaFactorId, label: String) {
        factors.computeIfPresent(id) { _, f -> f.copy(label = label) }
    }

    override suspend fun revokeFactor(id: MfaFactorId, at: Instant) {
        // A status update, exactly as in Postgres: the credential row is expected to survive it.
        factors.computeIfPresent(id) { _, f -> f.copy(status = MfaFactorStatus.REVOKED) }
    }

    override suspend fun touchFactor(id: MfaFactorId, at: Instant) {
        factors.computeIfPresent(id) { _, f -> f.copy(lastUsedAt = at) }
    }

    override suspend fun findTotp(factorId: MfaFactorId): TotpFactor? = null
    override suspend fun insertTotp(factor: TotpFactor) = Unit
    override suspend fun tryAdvanceTotpStep(factorId: MfaFactorId, step: Long): Boolean = false
    override suspend fun replaceRecoveryCodes(userId: UserId, codes: List<RecoveryCode>) = Unit
    override suspend fun listRecoveryCodes(userId: UserId): List<RecoveryCode> = emptyList()
    override suspend fun consumeRecoveryCode(userId: UserId, codeHash: String, at: Instant): Boolean = false
    override suspend fun countUnusedRecoveryCodes(userId: UserId): Int = 0
}

class FakeWebAuthnCredentialRepository : WebAuthnCredentialRepository {

    private val stored = mutableListOf<WebAuthnCredential>()

    override suspend fun listForUser(userId: UserId): List<WebAuthnCredential> =
        stored.filter { it.userId == userId }

    override suspend fun findByFactor(factorId: MfaFactorId): WebAuthnCredential? =
        stored.firstOrNull { it.factorId == factorId }

    override suspend fun findByCredentialId(userId: UserId, credentialId: ByteArray): WebAuthnCredential? =
        stored.firstOrNull { it.userId == userId && it.credentialId.contentEquals(credentialId) }

    override suspend fun insert(credential: WebAuthnCredential) {
        stored += credential
    }

    override suspend fun tryAdvanceSignatureCounter(
        factorId: MfaFactorId,
        counter: Long,
        at: Instant,
    ): Boolean {
        val index = stored.indexOfFirst { it.factorId == factorId }
        if (index < 0) return false
        val current = stored[index]
        // Conditional update: strictly greater, or nothing happens. Same rule the SQL enforces.
        if (counter <= current.signatureCounter) return false
        stored[index] = current.copy(signatureCounter = counter, lastUsedAt = at)
        return true
    }

    override suspend fun touch(factorId: MfaFactorId, at: Instant) {
        val index = stored.indexOfFirst { it.factorId == factorId }
        if (index >= 0) stored[index] = stored[index].copy(lastUsedAt = at)
    }

    /** Test-only: rewinds the authenticator's history to simulate a counter regression. */
    fun forceSignatureCounter(factorId: MfaFactorId, counter: Long) {
        val index = stored.indexOfFirst { it.factorId == factorId }
        stored[index] = stored[index].copy(signatureCounter = counter)
    }

    fun single(): WebAuthnCredential = stored.single()
}

/** Real randomness. Challenges are compared for uniqueness, never predicted. */
class TestRandomSource : RandomSource {

    private val random = SecureRandom()

    override fun bytes(length: Int): ByteArray = ByteArray(length).also(random::nextBytes)

    override fun token(byteLength: Int): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(byteLength))

    override fun humanCode(groups: Int, groupLength: Int): String = error("not used by the WebAuthn adapter")
}
