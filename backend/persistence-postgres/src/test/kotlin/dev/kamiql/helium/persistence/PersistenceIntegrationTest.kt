package dev.kamiql.helium.persistence

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.RefreshTokenFamilyId
import dev.kamiql.helium.domain.common.RefreshTokenId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.error.AuthErrorException
import dev.kamiql.helium.domain.event.VerificationPurpose
import dev.kamiql.helium.domain.identity.ExternalIdentity
import dev.kamiql.helium.domain.identity.Issuer
import dev.kamiql.helium.domain.identity.ProviderKey
import dev.kamiql.helium.domain.identity.ProviderSubject
import dev.kamiql.helium.domain.repository.StoredVerificationToken
import dev.kamiql.helium.domain.token.RefreshToken
import dev.kamiql.helium.domain.token.RefreshTokenFamily
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.persistence.repository.ExternalIdentityRepositoryImpl
import dev.kamiql.helium.persistence.repository.RefreshTokenRepositoryImpl
import dev.kamiql.helium.persistence.repository.UserRepositoryImpl
import dev.kamiql.helium.persistence.repository.VerificationTokenRepositoryImpl
import dev.kamiql.helium.testing.PostgresFixture
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Integration tests against a real PostgreSQL.
 *
 * Every assertion here is about something only the database can guarantee: a unique index
 * winning a race, a conditional UPDATE being atomic, a transaction rolling back cleanly.
 *
 * Tagged `integration` so `./gradlew build` stays fast and offline; run with
 * `./gradlew integrationTest`.
 */
@Tag("integration")
class PersistenceIntegrationTest {

    private val db = PostgresFixture.db
    private val users = UserRepositoryImpl(db)
    private val identities = ExternalIdentityRepositoryImpl(db)
    private val refreshTokens = RefreshTokenRepositoryImpl(db)
    private val verificationTokens = VerificationTokenRepositoryImpl(db)
    private val transactions = ExposedTransactionManager(db)

    private val now: Instant = Instant.parse("2026-08-12T10:00:00Z")

    @BeforeEach
    fun reset() {
        PostgresFixture.truncateAll()
    }

    private fun newUser(name: String = "alice"): User = User(
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

    @Test
    fun `migrations apply and the schema round trips a user`(): Unit = runBlocking {
        val user = users.insert(newUser())

        val loaded = assertNotNull(users.findById(user.id))
        assertEquals(user.username.normalized, loaded.username.normalized)
        // timestamptz must come back as the same instant, not shifted by the JVM's zone.
        assertEquals(now, loaded.createdAt)
    }

    @Test
    fun `a login identifier resolves by either username or email`(): Unit = runBlocking {
        users.insert(newUser("bob"))

        assertNotNull(users.findByLoginIdentifier("bob"))
        assertNotNull(users.findByLoginIdentifier("BOB"))
        assertNotNull(users.findByLoginIdentifier("bob@example.com"))
        assertNotNull(users.findByLoginIdentifier("Bob@Example.COM"))
        assertNull(users.findByLoginIdentifier("nobody"))
    }

    @Test
    fun `the normalized unique index blocks a case-variant duplicate`(): Unit = runBlocking {
        users.insert(newUser("carol"))

        // "CAROL" normalizes to "carol", so the database — not application code — rejects it.
        val duplicate = newUser().copy(
            id = UserId.random(),
            username = requireNotNull(Username.parse("CAROL")),
            primaryEmail = requireNotNull(EmailAddress.parse("other@example.com")),
        )
        assertFailsWith<Exception> { users.insert(duplicate) }
    }

    @Test
    fun `optimistic locking rejects a stale update`(): Unit = runBlocking {
        val user = users.insert(newUser("dave"))

        val updated = users.update(user.copy(firstName = "First", updatedAt = now))
        assertEquals(1, updated.version)

        // The second writer still holds version 0 and must lose rather than silently overwrite.
        val error = assertFailsWith<AuthErrorException> {
            users.update(user.copy(firstName = "Second", updatedAt = now))
        }
        assertEquals("conflict", error.error.code)
        assertEquals("First", assertNotNull(users.findById(user.id)).firstName)
    }

    @Test
    fun `a rolled back transaction leaves no partial state`(): Unit = runBlocking {
        val user = newUser("erin")

        assertFailsWith<IllegalStateException> {
            transactions.transaction {
                users.insert(user)
                // Simulates a later step failing after an earlier one already wrote.
                error("boom")
            }
        }

        assertNull(users.findById(user.id), "the insert must not have survived the rollback")
    }

    @Test
    fun `the issuer and subject unique index prevents linking one identity twice`(): Unit = runBlocking {
        val first = users.insert(newUser("frank"))
        val second = users.insert(newUser("grace"))

        val issuer = Issuer("https://accounts.google.com")
        val subject = ProviderSubject("google-subject-123")

        identities.link(
            ExternalIdentity(
                id = dev.kamiql.helium.domain.common.ExternalIdentityId.random(),
                userId = first.id,
                providerKey = ProviderKey("google"),
                issuer = issuer,
                subject = subject,
                providerEmail = null,
                createdAt = now,
                lastLoginAt = null,
            ),
        )

        // The takeover attempt: a second account claiming the same provider identity.
        val error = assertFailsWith<AuthErrorException> {
            identities.link(
                ExternalIdentity(
                    id = dev.kamiql.helium.domain.common.ExternalIdentityId.random(),
                    userId = second.id,
                    providerKey = ProviderKey("google"),
                    issuer = issuer,
                    subject = subject,
                    providerEmail = null,
                    createdAt = now,
                    lastLoginAt = null,
                ),
            )
        }
        assertEquals("identity_already_linked", error.error.code)
        assertEquals(first.id, assertNotNull(identities.findByIssuerAndSubject(issuer, subject)).userId)
    }

    @Test
    fun `only one concurrent refresh rotation can mark a token used`(): Unit = runBlocking {
        val user = users.insert(newUser("heidi"))
        val client = insertClient("concurrent-client")

        val family = refreshTokens.createFamily(
            RefreshTokenFamily(
                id = RefreshTokenFamilyId.random(),
                userId = user.id,
                clientId = client,
                sessionId = null,
                scopes = setOf("openid"),
                authenticationMethods = emptySet(),
                createdAt = now,
                absoluteExpiresAt = now.plusSeconds(86_400),
                revokedAt = null,
                reuseDetectedAt = null,
            ),
        )
        val token = refreshTokens.insertToken(
            RefreshToken(
                id = RefreshTokenId.random(),
                familyId = family.id,
                tokenHash = "hash-of-the-only-token",
                issuedAt = now,
                expiresAt = now.plusSeconds(3_600),
                usedAt = null,
                revokedAt = null,
                replacedByTokenId = null,
            ),
        )

        // Eight clients present the same refresh token at the same moment. Exactly one may win;
        // every other attempt is, by definition, indistinguishable from a stolen-token replay.
        val outcomes = coroutineScope {
            (1..8).map {
                async { refreshTokens.markUsed(token.id, now, RefreshTokenId.random()) }
            }.awaitAll()
        }

        assertEquals(1, outcomes.count { it }, "exactly one rotation must succeed")
        assertEquals(7, outcomes.count { !it })
    }

    @Test
    fun `revoking a family revokes its tokens and records the reuse signal`(): Unit = runBlocking {
        val user = users.insert(newUser("ivan"))
        val client = insertClient("family-client")

        val family = refreshTokens.createFamily(
            RefreshTokenFamily(
                id = RefreshTokenFamilyId.random(),
                userId = user.id,
                clientId = client,
                sessionId = null,
                scopes = setOf("openid"),
                authenticationMethods = emptySet(),
                createdAt = now,
                absoluteExpiresAt = now.plusSeconds(86_400),
                revokedAt = null,
                reuseDetectedAt = null,
            ),
        )
        repeat(3) { index ->
            refreshTokens.insertToken(
                RefreshToken(
                    id = RefreshTokenId.random(),
                    familyId = family.id,
                    tokenHash = "hash-$index",
                    issuedAt = now,
                    expiresAt = now.plusSeconds(3_600),
                    usedAt = null,
                    revokedAt = null,
                    replacedByTokenId = null,
                ),
            )
        }

        refreshTokens.revokeFamily(family.id, now, reuseDetected = true)

        val reloaded = assertNotNull(refreshTokens.findFamily(family.id))
        assertNotNull(reloaded.reuseDetectedAt, "the reuse signal must be recorded, not just the revocation")
        assertFalse(reloaded.isActive(now))
        repeat(3) { index ->
            assertNotNull(assertNotNull(refreshTokens.findByHash("hash-$index")).revokedAt)
        }
    }

    @Test
    fun `a verification token can only be consumed once`(): Unit = runBlocking {
        val user = users.insert(newUser("judy"))
        verificationTokens.insert(
            StoredVerificationToken(
                id = dev.kamiql.helium.domain.common.VerificationTokenId.random(),
                userId = user.id,
                tokenHash = "reset-token-hash",
                purpose = VerificationPurpose.PASSWORD_RESET,
                payload = null,
                expiresAt = now.plusSeconds(900),
                usedAt = null,
                createdAt = now,
            ),
        )

        assertTrue(verificationTokens.consume("reset-token-hash", VerificationPurpose.PASSWORD_RESET, now))
        // Replay.
        assertFalse(verificationTokens.consume("reset-token-hash", VerificationPurpose.PASSWORD_RESET, now))
    }

    @Test
    fun `a token issued for one purpose cannot be redeemed for another`(): Unit = runBlocking {
        val user = users.insert(newUser("karl"))
        verificationTokens.insert(
            StoredVerificationToken(
                id = dev.kamiql.helium.domain.common.VerificationTokenId.random(),
                userId = user.id,
                tokenHash = "shared-hash",
                purpose = VerificationPurpose.EMAIL_VERIFICATION,
                payload = null,
                expiresAt = now.plusSeconds(900),
                usedAt = null,
                createdAt = now,
            ),
        )

        // Even knowing the token, it cannot be escalated into a password reset.
        assertNull(verificationTokens.findByHash("shared-hash", VerificationPurpose.PASSWORD_RESET))
        assertFalse(verificationTokens.consume("shared-hash", VerificationPurpose.PASSWORD_RESET, now))
        assertTrue(verificationTokens.consume("shared-hash", VerificationPurpose.EMAIL_VERIFICATION, now))
    }

    @Test
    fun `an expired token cannot be consumed`(): Unit = runBlocking {
        val user = users.insert(newUser("lena"))
        verificationTokens.insert(
            StoredVerificationToken(
                id = dev.kamiql.helium.domain.common.VerificationTokenId.random(),
                userId = user.id,
                tokenHash = "expired-hash",
                purpose = VerificationPurpose.PASSWORD_RESET,
                payload = null,
                expiresAt = now.minusSeconds(1),
                usedAt = null,
                createdAt = now.minusSeconds(1_000),
            ),
        )

        assertFalse(verificationTokens.consume("expired-hash", VerificationPurpose.PASSWORD_RESET, now))
    }

    /** Minimal client row, since refresh families carry a foreign key to one. */
    private fun insertClient(id: String): dev.kamiql.helium.domain.common.ClientId {
        PostgresFixture.container.createConnection("").use { connection ->
            connection.prepareStatement(
                """
                INSERT INTO oauth_clients
                    (client_id, name, type, secret_hash, skip_consent, audiences, grant_types,
                     enabled, created_at, updated_at)
                VALUES (?, ?, 'PUBLIC', NULL, false, '', 'authorization_code,refresh_token',
                        true, now(), now())
                """.trimIndent(),
            ).use { statement ->
                statement.setString(1, id)
                statement.setString(2, id)
                statement.executeUpdate()
            }
        }
        return dev.kamiql.helium.domain.common.ClientId(id)
    }
}
