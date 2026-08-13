package dev.kamiql.helium.persistence

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.MfaFactorId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.mfa.MfaFactor
import dev.kamiql.helium.domain.mfa.MfaFactorStatus
import dev.kamiql.helium.domain.mfa.MfaType
import dev.kamiql.helium.domain.mfa.WebAuthnCredential
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.persistence.repository.MfaRepositoryImpl
import dev.kamiql.helium.persistence.repository.UserRepositoryImpl
import dev.kamiql.helium.persistence.repository.WebAuthnCredentialRepositoryImpl
import dev.kamiql.helium.testing.PostgresFixture
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.sql.SQLException
import java.time.Instant
import java.util.UUID
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Integration tests for [WebAuthnCredentialRepositoryImpl] against a real PostgreSQL.
 *
 * The things worth testing here are the ones a mock cannot have: `bytea` surviving a round trip
 * and comparing correctly in a WHERE clause, the conditional UPDATE that makes the signature
 * counter a genuine replay guard under concurrency, the `(user_id, credential_id)` predicate that
 * stops an assertion crossing accounts, and the V4 foreign key that ties a credential to its
 * owning factor in both directions.
 */
@Tag("integration")
class WebAuthnCredentialIntegrationTest {

    private val db = PostgresFixture.db
    private val users = UserRepositoryImpl(db)
    private val factors = MfaRepositoryImpl(db)
    private val credentials = WebAuthnCredentialRepositoryImpl(db)

    private val now: Instant = Instant.parse("2026-08-13T09:00:00Z")
    private val later: Instant = now.plusSeconds(3_600)

    @BeforeEach
    fun reset() {
        PostgresFixture.truncateAll()
        assertEquals(0, countCredentials(), "the fixture must leave no credentials behind")
    }

    // -----------------------------------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------------------------------

    @Test
    fun `insert round trips every column including the byte arrays`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        val factor = factors.insertFactor(newFactor(user.id, "Yubikey"))

        // Bytes chosen to break a mapper that goes through a String: a NUL, a high byte, and a
        // sequence that is not valid UTF-8. `credential_id` is attacker-influenced, so a lossy
        // conversion here would be a collision the unique index could not see.
        val credentialId = byteArrayOf(0x00, 0x7F, -0x01, -0x80, 0x41, 0x00, -0x2E)
        val publicKey = ByteArray(96) { (it * 7 - 128).toByte() }
        val aaguid = UUID.fromString("f8a011f3-8c0a-4d15-8006-17111f9edc7d")

        val stored = newCredential(
            factorId = factor.id,
            userId = user.id,
            credentialId = credentialId,
            publicKey = publicKey,
            signatureCounter = 42,
            aaguid = aaguid,
            transports = "usb,nfc",
            userVerifiedRequired = true,
            backupEligible = true,
            backupState = true,
            lastUsedAt = later,
        )
        credentials.insert(stored)

        val loaded = assertNotNull(credentials.findByFactor(factor.id))
        assertEquals(factor.id, loaded.factorId)
        assertEquals(user.id, loaded.userId)
        assertContentEquals(credentialId, loaded.credentialId)
        assertContentEquals(publicKey, loaded.publicKey)
        assertEquals(42L, loaded.signatureCounter)
        assertEquals(aaguid, loaded.aaguid)
        assertEquals("usb,nfc", loaded.transports)
        assertTrue(loaded.userVerifiedRequired)
        assertTrue(loaded.backupEligible)
        assertTrue(loaded.backupState)
        assertEquals("login.example.com", loaded.rpId)
        // timestamptz must come back as the same instant, not shifted by the JVM's zone.
        assertEquals(now, loaded.createdAt)
        assertEquals(later, loaded.lastUsedAt)

        // The shape a freshly registered hardware key actually has: no aaguid, never used.
        val bareFactor = factors.insertFactor(newFactor(user.id, "Bare key"))
        credentials.insert(
            newCredential(
                factorId = bareFactor.id,
                userId = user.id,
                credentialId = byteArrayOf(0x01),
                aaguid = null,
                transports = "",
                lastUsedAt = null,
            ),
        )
        val bare = assertNotNull(credentials.findByFactor(bareFactor.id))
        assertNull(bare.aaguid)
        assertNull(bare.lastUsedAt)
        assertEquals("", bare.transports)
        assertEquals(0L, bare.signatureCounter)
    }

    @Test
    fun `listForUser returns only this user's credentials`(): Unit = runBlocking {
        val user = users.insert(newUser("bob"))
        val bystander = users.insert(newUser("carol"))

        val first = factors.insertFactor(newFactor(user.id, "Phone"))
        val second = factors.insertFactor(newFactor(user.id, "Laptop"))
        val other = factors.insertFactor(newFactor(bystander.id, "Their phone"))

        credentials.insert(newCredential(first.id, user.id, byteArrayOf(0x0A)))
        credentials.insert(newCredential(second.id, user.id, byteArrayOf(0x0B)))
        credentials.insert(newCredential(other.id, bystander.id, byteArrayOf(0x0C)))

        // This list becomes `excludeCredentials` and `allowCredentials`. A stranger's id leaking
        // into it would name someone else's authenticator in a ceremony for this account.
        assertEquals(setOf(first.id, second.id), credentials.listForUser(user.id).map { it.factorId }.toSet())
        assertEquals(listOf(other.id), credentials.listForUser(bystander.id).map { it.factorId })
        assertEquals(emptyList(), credentials.listForUser(UserId.random()))
    }

    // -----------------------------------------------------------------------------------------
    // Lookup by credential id
    // -----------------------------------------------------------------------------------------

    @Test
    fun `findByCredentialId matches the exact bytes and never another account's credential`(): Unit = runBlocking {
        val owner = users.insert(newUser("dave"))
        val attacker = users.insert(newUser("mallory"))
        val factor = factors.insertFactor(newFactor(owner.id, "Owner key"))

        val credentialId = byteArrayOf(0x10, 0x20, 0x30, -0x01)
        credentials.insert(newCredential(factor.id, owner.id, credentialId))

        // A separate array with equal contents: the predicate has to be a real bytea comparison,
        // not reference identity smuggled through a parameter.
        val equalBytes = byteArrayOf(0x10, 0x20, 0x30, -0x01)
        assertEquals(factor.id, assertNotNull(credentials.findByCredentialId(owner.id, equalBytes)).factorId)

        // Credential ids arrive from the client. Resolving one globally would let an assertion
        // produced for the owner's account be replayed against the attacker's — a full takeover
        // of whichever account the attacker controls, using a factor they do not hold.
        assertNull(credentials.findByCredentialId(attacker.id, credentialId))

        // Near misses must not match: a prefix, a suffix, and a single flipped byte.
        assertNull(credentials.findByCredentialId(owner.id, byteArrayOf(0x10, 0x20, 0x30)))
        assertNull(credentials.findByCredentialId(owner.id, byteArrayOf(0x10, 0x20, 0x30, -0x01, 0x00)))
        assertNull(credentials.findByCredentialId(owner.id, byteArrayOf(0x10, 0x20, 0x31, -0x01)))
        assertNull(credentials.findByCredentialId(owner.id, ByteArray(0)))
    }

    @Test
    fun `the same credential id cannot be registered twice`(): Unit = runBlocking {
        val owner = users.insert(newUser("erin"))
        val attacker = users.insert(newUser("oscar"))
        val credentialId = byteArrayOf(0x55, 0x66)

        credentials.insert(
            newCredential(factors.insertFactor(newFactor(owner.id, "Key")).id, owner.id, credentialId),
        )

        // Claiming a credential id already bound elsewhere is the account-linking takeover: the
        // authenticator would then resolve to two accounts and the lookup's scoping would decide
        // which. The unique index from V1 is what makes it impossible rather than merely unlikely.
        val duplicate = factors.insertFactor(newFactor(attacker.id, "Copy"))
        assertFailsWith<SQLException> {
            credentials.insert(newCredential(duplicate.id, attacker.id, credentialId))
        }
        assertEquals(1, countCredentials())
    }

    // -----------------------------------------------------------------------------------------
    // Signature counter
    // -----------------------------------------------------------------------------------------

    @Test
    fun `the counter advances only forwards and records the use`(): Unit = runBlocking {
        val user = users.insert(newUser("frank"))
        val factor = factors.insertFactor(newFactor(user.id, "Counting key"))
        credentials.insert(newCredential(factor.id, user.id, byteArrayOf(0x01), signatureCounter = 5))

        assertTrue(credentials.tryAdvanceSignatureCounter(factor.id, 6, later))
        val advanced = assertNotNull(credentials.findByFactor(factor.id))
        assertEquals(6L, advanced.signatureCounter)
        assertEquals(later, advanced.lastUsedAt)

        // Equal or lower is the cloned-authenticator signal (WebAuthn L3 §6.1.1 step 21): a second
        // device holding a copy of the key reports a counter that has not moved past what the
        // original already used. Accepting it would make the counter decorative.
        assertFalse(credentials.tryAdvanceSignatureCounter(factor.id, 6, later.plusSeconds(60)))
        assertFalse(credentials.tryAdvanceSignatureCounter(factor.id, 5, later.plusSeconds(60)))
        assertFalse(credentials.tryAdvanceSignatureCounter(factor.id, 0, later.plusSeconds(60)))

        val unchanged = assertNotNull(credentials.findByFactor(factor.id))
        assertEquals(6L, unchanged.signatureCounter)
        // A rejected attempt must not even count as a use — `last_used_at` would otherwise report
        // activity for an assertion the server refused.
        assertEquals(later, unchanged.lastUsedAt)

        // A missing factor is a miss, not a write.
        assertFalse(credentials.tryAdvanceSignatureCounter(MfaFactorId.random(), 99, later))
    }

    @Test
    fun `an authenticator that always reports zero never advances`(): Unit = runBlocking {
        val user = users.insert(newUser("grace"))
        val factor = factors.insertFactor(newFactor(user.id, "Zero-counter key"))
        credentials.insert(newCredential(factor.id, user.id, byteArrayOf(0x02), signatureCounter = 0))

        // Plenty of authenticators legitimately never keep a counter. The repository reports the
        // fact and stays out of the policy decision; `touch` is the caller's route for these.
        assertFalse(credentials.tryAdvanceSignatureCounter(factor.id, 0, later))

        credentials.touch(factor.id, later)
        val touched = assertNotNull(credentials.findByFactor(factor.id))
        assertEquals(later, touched.lastUsedAt)
        assertEquals(0L, touched.signatureCounter)
    }

    @Test
    fun `only one concurrent assertion with the same counter can succeed`(): Unit = runBlocking {
        val user = users.insert(newUser("heidi"))
        val factor = factors.insertFactor(newFactor(user.id, "Contested key"))
        credentials.insert(newCredential(factor.id, user.id, byteArrayOf(0x03), signatureCounter = 10))

        // The replay this guards against is inherently concurrent: an attacker who captured an
        // assertion submits it alongside the genuine one. A read-then-write would let both observe
        // 10, both decide 11 is an advance, and both be accepted.
        val outcomes = coroutineScope {
            (1..8).map { async { credentials.tryAdvanceSignatureCounter(factor.id, 11, later) } }.awaitAll()
        }

        assertEquals(1, outcomes.count { it }, "exactly one assertion must be accepted")
        assertEquals(11L, assertNotNull(credentials.findByFactor(factor.id)).signatureCounter)
    }

    // -----------------------------------------------------------------------------------------
    // Factor binding
    // -----------------------------------------------------------------------------------------

    @Test
    fun `deleting the owning factor takes the credential with it`(): Unit = runBlocking {
        val user = users.insert(newUser("ivan"))
        val factor = factors.insertFactor(newFactor(user.id, "Doomed key"))
        credentials.insert(newCredential(factor.id, user.id, byteArrayOf(0x04)))

        // The V4 cascade. Without it the public key would outlive the factor that carries its
        // status, so a credential id could still be resolved for an authenticator the account no
        // longer lists — and would be reachable again if the factor UUID were ever reissued.
        deleteFactorRow(factor.id)

        assertNull(credentials.findByFactor(factor.id))
        assertNull(credentials.findByCredentialId(user.id, byteArrayOf(0x04)))
        assertEquals(0, countCredentials())
    }

    @Test
    fun `deleting the owning user takes the credential with it`(): Unit = runBlocking {
        val user = users.insert(newUser("judy"))
        val factor = factors.insertFactor(newFactor(user.id, "Erasable key"))
        credentials.insert(newCredential(factor.id, user.id, byteArrayOf(0x05)))

        deleteUserRow(user.id)

        assertEquals(0, countCredentials())
    }

    @Test
    fun `a credential cannot exist without a factor`(): Unit = runBlocking {
        val user = users.insert(newUser("karl"))

        // The identity `webauthn_credentials.id = mfa_factors.id` is what lets a passkey be
        // listed, labelled and revoked through the generic factor endpoints. An orphan row would
        // be a registered authenticator invisible to every one of them.
        assertFailsWith<SQLException> {
            credentials.insert(newCredential(MfaFactorId.random(), user.id, byteArrayOf(0x06)))
        }
        assertEquals(0, countCredentials())
    }

    @Test
    fun `revoking the factor leaves the credential in place`(): Unit = runBlocking {
        val user = users.insert(newUser("lena"))
        val factor = factors.insertFactor(newFactor(user.id, "Revoked key"))
        credentials.insert(newCredential(factor.id, user.id, byteArrayOf(0x07)))

        factors.revokeFactor(factor.id, later)

        // Revocation is a status change on the factor, not a delete, so the credential stays —
        // and staying is what keeps the unique index on `credential_id` meaningful: a revoked
        // authenticator must not be silently re-registrable as if it were new. Whoever reads this
        // repository is therefore responsible for checking the factor's status; the row's presence
        // is not by itself permission to authenticate.
        assertNotNull(credentials.findByFactor(factor.id))
        assertEquals(MfaFactorStatus.REVOKED, assertNotNull(factors.findFactor(factor.id)).status)
    }

    // -----------------------------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------------------------

    private fun newUser(name: String): User = User(
        id = UserId.random(),
        username = requireNotNull(Username.parse(name)),
        primaryEmail = requireNotNull(EmailAddress.parse("$name@example.com")),
        firstName = "Test",
        lastName = "User",
        status = UserStatus.ACTIVE,
        emailVerifiedAt = now,
        createdAt = now,
        updatedAt = now,
        version = 0,
    )

    private fun newFactor(userId: UserId, label: String): MfaFactor = MfaFactor(
        id = MfaFactorId.random(),
        userId = userId,
        type = MfaType.WEBAUTHN,
        label = label,
        status = MfaFactorStatus.ACTIVE,
        createdAt = now,
        lastUsedAt = null,
    )

    private fun newCredential(
        factorId: MfaFactorId,
        userId: UserId,
        credentialId: ByteArray,
        publicKey: ByteArray = byteArrayOf(0x30, -0x1E, 0x02, 0x01),
        signatureCounter: Long = 0,
        aaguid: UUID? = null,
        transports: String = "internal",
        userVerifiedRequired: Boolean = false,
        backupEligible: Boolean = false,
        backupState: Boolean = false,
        lastUsedAt: Instant? = null,
    ): WebAuthnCredential = WebAuthnCredential(
        factorId = factorId,
        userId = userId,
        credentialId = credentialId,
        publicKey = publicKey,
        signatureCounter = signatureCounter,
        aaguid = aaguid,
        transports = transports,
        userVerifiedRequired = userVerifiedRequired,
        backupEligible = backupEligible,
        backupState = backupState,
        rpId = "login.example.com",
        createdAt = now,
        lastUsedAt = lastUsedAt,
    )

    /** Hard delete of the factor row, which [MfaRepositoryImpl] deliberately does not offer. */
    private fun deleteFactorRow(factorId: MfaFactorId) = executeDelete("mfa_factors", factorId.value)

    private fun deleteUserRow(userId: UserId) = executeDelete("users", userId.value)

    private fun executeDelete(table: String, id: UUID) {
        PostgresFixture.container.createConnection("").use { connection ->
            connection.prepareStatement("DELETE FROM $table WHERE id = ?").use { statement ->
                statement.setObject(1, id)
                statement.executeUpdate()
            }
        }
    }

    private fun countCredentials(): Int =
        PostgresFixture.container.createConnection("").use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery("SELECT count(*) FROM webauthn_credentials").use { rows ->
                    rows.next()
                    rows.getInt(1)
                }
            }
        }
}
