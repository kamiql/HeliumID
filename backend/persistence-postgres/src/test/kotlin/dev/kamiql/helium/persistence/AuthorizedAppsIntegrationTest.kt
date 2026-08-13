package dev.kamiql.helium.persistence

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.Consent
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.ConsentId
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.RefreshTokenFamilyId
import dev.kamiql.helium.domain.common.RefreshTokenId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.token.RefreshToken
import dev.kamiql.helium.domain.token.RefreshTokenFamily
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.persistence.repository.ClientRepositoryImpl
import dev.kamiql.helium.persistence.repository.ConsentRepositoryImpl
import dev.kamiql.helium.persistence.repository.RefreshTokenRepositoryImpl
import dev.kamiql.helium.persistence.repository.UserRepositoryImpl
import dev.kamiql.helium.testing.PostgresFixture
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The queries behind "which applications hold access to my account", against a real PostgreSQL.
 *
 * Both of the methods under test are predicates rather than logic — which is exactly why they
 * need a database. `absolute_expires_at > now`, `revoked_at IS NULL` and the `(user_id,
 * client_id)` scoping decide whether an application shows up in the list and whether revoking one
 * of them touches another user's tokens; a fake would agree with whatever the fake's author
 * believed the SQL said.
 *
 * Tagged `integration` like its siblings; run with `./gradlew integrationTest`.
 */
@Tag("integration")
class AuthorizedAppsIntegrationTest {

    private val db = PostgresFixture.db
    private val users = UserRepositoryImpl(db)
    private val clients = ClientRepositoryImpl(db)
    private val consents = ConsentRepositoryImpl(db)
    private val refreshTokens = RefreshTokenRepositoryImpl(db)

    private val now: Instant = Instant.parse("2026-08-12T10:00:00Z")
    private val later: Instant = now.plusSeconds(3_600)

    @BeforeEach
    fun reset() {
        PostgresFixture.truncateAll()
    }

    // --- listing ---------------------------------------------------------------------------

    @Test
    fun `only live families are listed, newest first`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        val client = registerClient("demo-app")

        val old = insertFamily(user.id, client, createdAt = now)
        val fresh = insertFamily(user.id, client, createdAt = later)
        insertFamily(user.id, client, createdAt = now, revokedAt = now)
        insertFamily(user.id, client, createdAt = now, reuseDetectedAt = now)
        // Expired: the absolute window has closed, so it can no longer mint anything.
        insertFamily(user.id, client, createdAt = now, expiresAt = now.plusSeconds(60))

        val listed = refreshTokens.listActiveFamiliesForUser(user.id, later)

        assertEquals(listOf(fresh.id, old.id), listed.map { it.id })
    }

    @Test
    fun `the expiry boundary is exclusive`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        val client = registerClient("demo-app")
        insertFamily(user.id, client, expiresAt = later)

        assertEquals(1, refreshTokens.listActiveFamiliesForUser(user.id, later.minusSeconds(1)).size)
        // A family whose window closes exactly now is done — `>` not `>=`.
        assertTrue(refreshTokens.listActiveFamiliesForUser(user.id, later).isEmpty())
    }

    @Test
    fun `another user's families are never listed`(): Unit = runBlocking {
        val owner = users.insert(newUser("alice"))
        val stranger = users.insert(newUser("mallory"))
        val client = registerClient("demo-app")
        insertFamily(owner.id, client)

        assertTrue(refreshTokens.listActiveFamiliesForUser(stranger.id, now).isEmpty())
    }

    @Test
    fun `every column survives the round trip`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        val client = registerClient("demo-app")
        val seeded = insertFamily(user.id, client, scopes = setOf("openid", "profile"))

        val listed = refreshTokens.listActiveFamiliesForUser(user.id, now).single()

        assertEquals(seeded.id, listed.id)
        assertEquals(client, listed.clientId)
        assertEquals(setOf("openid", "profile"), listed.scopes)
        assertEquals(setOf(AuthenticationMethod.PASSWORD), listed.authenticationMethods)
        assertEquals(now, listed.createdAt)
        assertNull(listed.revokedAt)
    }

    // --- revocation --------------------------------------------------------------------------

    @Test
    fun `revoking a client kills its families and their tokens`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        val client = registerClient("demo-app")
        val family = insertFamily(user.id, client)
        val token = insertToken(family.id)

        val revoked = refreshTokens.revokeFamiliesForUserAndClient(user.id, client, later)

        assertEquals(1, revoked)
        assertEquals(later, assertNotNull(refreshTokens.findFamily(family.id)).revokedAt)
        // The tokens go with the family: leaving a live row behind would let the next refresh
        // succeed against a family that is supposed to be dead.
        assertEquals(later, assertNotNull(refreshTokens.findByHash(token.tokenHash)).revokedAt)
        assertTrue(refreshTokens.listActiveFamiliesForUser(user.id, later).isEmpty())
    }

    @Test
    fun `revocation is scoped to the one client`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        val revokedClient = registerClient("demo-app")
        val keptClient = registerClient("helium-console")
        insertFamily(user.id, revokedClient)
        val kept = insertFamily(user.id, keptClient)

        assertEquals(1, refreshTokens.revokeFamiliesForUserAndClient(user.id, revokedClient, later))

        assertEquals(listOf(kept.id), refreshTokens.listActiveFamiliesForUser(user.id, later).map { it.id })
    }

    @Test
    fun `revocation is scoped to the one user`(): Unit = runBlocking {
        // The ownership check *is* this predicate. Without `user_id` in the WHERE clause, one
        // account owner could sign every other user out of an application they share.
        val owner = users.insert(newUser("alice"))
        val other = users.insert(newUser("bob"))
        val client = registerClient("demo-app")
        insertFamily(owner.id, client)
        val untouched = insertFamily(other.id, client)

        assertEquals(1, refreshTokens.revokeFamiliesForUserAndClient(owner.id, client, later))

        assertEquals(listOf(untouched.id), refreshTokens.listActiveFamiliesForUser(other.id, later).map { it.id })
    }

    @Test
    fun `a second revoke reports nothing to do`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        val client = registerClient("demo-app")
        insertFamily(user.id, client)

        assertEquals(1, refreshTokens.revokeFamiliesForUserAndClient(user.id, client, later))
        // Already-revoked rows are skipped, so the count is the caller's signal that this call
        // actually did something — the route turns "nothing at all" into a 404.
        assertEquals(0, refreshTokens.revokeFamiliesForUserAndClient(user.id, client, later.plusSeconds(60)))
    }

    @Test
    fun `revoking a client the user never used reports zero`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))
        registerClient("demo-app")

        assertEquals(0, refreshTokens.revokeFamiliesForUserAndClient(user.id, ClientId("demo-app"), later))
    }

    @Test
    fun `a consent and the token families are independent halves of the same revocation`(): Unit =
        runBlocking {
            // The listing merges both sources, so the revocation has to clear both. This asserts
            // they really are separate rows: clearing one leaves the other standing.
            val user = users.insert(newUser("alice"))
            val client = registerClient("demo-app")
            consents.grant(
                Consent(
                    id = ConsentId.random(),
                    userId = user.id,
                    clientId = client,
                    grantedScopes = setOf("openid", "profile"),
                    grantedAt = now,
                    revokedAt = null,
                ),
            )
            insertFamily(user.id, client)

            assertTrue(consents.revoke(user.id, client, later))
            assertTrue(consents.listForUser(user.id).isEmpty())
            assertEquals(1, refreshTokens.listActiveFamiliesForUser(user.id, later).size)

            assertEquals(1, refreshTokens.revokeFamiliesForUserAndClient(user.id, client, later))
            // And a second consent revoke reports false, which is what makes the flow's
            // "nothing happened -> NotFound" answer correct rather than merely plausible.
            assertFalse(consents.revoke(user.id, client, later))
        }

    // --- helpers ------------------------------------------------------------------------------

    private suspend fun registerClient(id: String): ClientId {
        val clientId = ClientId(id)
        clients.insert(
            OAuthClient(
                clientId = clientId,
                name = "Client $id",
                type = ClientType.PUBLIC,
                secretHash = null,
                secretRotatedAt = null,
                redirectUris = setOf("https://$id.example.test/callback"),
                allowedScopes = setOf("openid", "profile"),
                allowedGrantTypes = setOf(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                skipConsent = false,
                audiences = setOf("api"),
                enabled = true,
                createdAt = now,
                updatedAt = now,
            ),
        )
        return clientId
    }

    private suspend fun insertFamily(
        userId: UserId,
        clientId: ClientId,
        scopes: Set<String> = setOf("openid"),
        createdAt: Instant = now,
        expiresAt: Instant = now.plusSeconds(30L * 86_400),
        revokedAt: Instant? = null,
        reuseDetectedAt: Instant? = null,
    ): RefreshTokenFamily = refreshTokens.createFamily(
        RefreshTokenFamily(
            id = RefreshTokenFamilyId.random(),
            userId = userId,
            clientId = clientId,
            sessionId = null,
            scopes = scopes,
            authenticationMethods = setOf(AuthenticationMethod.PASSWORD),
            createdAt = createdAt,
            absoluteExpiresAt = expiresAt,
            revokedAt = revokedAt,
            reuseDetectedAt = reuseDetectedAt,
        ),
    )

    private suspend fun insertToken(familyId: RefreshTokenFamilyId): RefreshToken =
        refreshTokens.insertToken(
            RefreshToken(
                id = RefreshTokenId.random(),
                familyId = familyId,
                tokenHash = "hash-${familyId.value}",
                issuedAt = now,
                expiresAt = now.plusSeconds(86_400),
                usedAt = null,
                revokedAt = null,
                replacedByTokenId = null,
            ),
        )

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
}
