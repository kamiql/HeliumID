package dev.kamiql.helium.persistence

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.persistence.repository.ClientRepositoryImpl
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
 * The scope catalogue against a real PostgreSQL.
 *
 * Three things here cannot be tested against a fake. The V5 migration's back-fill — whether the
 * four OIDC scopes actually came out flagged. The `onUpdateExclude` on the upsert, which is what
 * stops an edit from rewriting `created_at` or flipping `built_in`. And the `ON DELETE CASCADE`
 * on `oauth_client_scopes`, which is the reason the delete flow refuses a scope that is still in
 * use: the database will happily strip it from every client without a word.
 */
@Tag("integration")
class ScopeCatalogueIntegrationTest {

    private val db = PostgresFixture.db
    private val clients = ClientRepositoryImpl(db)

    private val now: Instant = Instant.parse("2026-08-13T09:00:00Z")
    private val later: Instant = now.plusSeconds(3_600)

    /**
     * `truncateAll` deliberately spares `oauth_scopes` as reference data, so a scope written by
     * one test would survive into the next. Remove the ones the tests add, and only those.
     */
    @BeforeEach
    fun reset() {
        PostgresFixture.truncateAll()
        execute("DELETE FROM oauth_scopes WHERE built_in = false")
        assertEquals(Scope.BUILT_IN_NAMES.size, countScopes(), "only the seeded scopes should remain")
    }

    // --- the migration ------------------------------------------------------------------

    @Test
    fun `V5 flags exactly the four standard scopes`(): Unit = runBlocking {
        val byName = clients.listScopes().associateBy { it.name }

        assertEquals(Scope.BUILT_IN_NAMES, byName.keys)
        Scope.BUILT_IN_NAMES.forEach { name ->
            assertTrue(byName.getValue(name).builtIn, "$name must be built in")
        }
        // `openid` is the one scope a user cannot decline, so it must stay off the consent screen.
        assertTrue(byName.getValue(Scope.OPENID).implicit)
        assertFalse(byName.getValue(Scope.PROFILE).implicit)
    }

    // --- upsert -------------------------------------------------------------------------

    @Test
    fun `a new scope round trips`(): Unit = runBlocking {
        val saved = clients.upsertScope(
            Scope("workspace:read", "See your documents", implicit = false, builtIn = false),
            now,
        )

        assertEquals("workspace:read", saved.name)
        assertEquals("See your documents", saved.description)
        assertFalse(saved.builtIn)
        assertEquals(saved, clients.findScope("workspace:read"))
    }

    @Test
    fun `upsert is idempotent and keeps the original creation time`(): Unit = runBlocking {
        clients.upsertScope(Scope("workspace:read", "See your documents"), now)
        clients.upsertScope(Scope("workspace:read", "Read documents you can access"), later)

        assertEquals(Scope.BUILT_IN_NAMES.size + 1, countScopes())
        assertEquals("Read documents you can access", clients.findScope("workspace:read")?.description)
        // Rewriting created_at on every edit would turn the audit question "when was this scope
        // introduced" into "when was it last touched".
        assertEquals(now, createdAtOf("workspace:read"))
    }

    /**
     * The guard behind `onUpdateExclude`. The flow refuses built-in scopes long before reaching
     * the repository, but a repository that let the flag be overwritten would make that the only
     * thing standing between an administrator and a deletable `openid`.
     */
    @Test
    fun `an upsert cannot clear the built-in flag`(): Unit = runBlocking {
        clients.upsertScope(Scope(Scope.OPENID, "Hijacked", implicit = false, builtIn = false), later)

        val stored = assertNotNull(clients.findScope(Scope.OPENID))
        assertTrue(stored.builtIn, "built_in must survive an update")
    }

    // --- usage and deletion ---------------------------------------------------------------

    @Test
    fun `clientsUsingScope counts only the clients that list it`(): Unit = runBlocking {
        clients.upsertScope(Scope("workspace:read", "See your documents"), now)
        clients.upsertScope(Scope("workspace:write", "Edit your documents"), now)
        clients.insert(client("reader", setOf(Scope.OPENID, "workspace:read")))
        clients.insert(client("editor", setOf("workspace:read", "workspace:write")))

        assertEquals(2, clients.clientsUsingScope("workspace:read"))
        assertEquals(1, clients.clientsUsingScope("workspace:write"))
        assertEquals(0, clients.clientsUsingScope("workspace:admin"))
    }

    @Test
    fun `an unused scope deletes and an unknown one reports false`(): Unit = runBlocking {
        clients.upsertScope(Scope("workspace:read", "See your documents"), now)

        assertTrue(clients.deleteScope("workspace:read"))
        assertNull(clients.findScope("workspace:read"))
        assertFalse(clients.deleteScope("workspace:read"))
    }

    /**
     * Documents the hazard the delete flow exists to prevent, rather than asserting it is safe.
     *
     * Postgres cascades the row out of `oauth_client_scopes`, so the client silently loses a
     * scope it was registered with and the failure appears later as `invalid_scope` on an
     * authorization request. Nothing at this layer can refuse — hence the check in the flow.
     */
    @Test
    fun `deleting a scope in use cascades and strips it from the client`(): Unit = runBlocking {
        clients.upsertScope(Scope("workspace:read", "See your documents"), now)
        clients.insert(client("reader", setOf(Scope.OPENID, "workspace:read")))

        clients.deleteScope("workspace:read")

        val stored = assertNotNull(clients.findById(ClientId("reader")))
        assertEquals(setOf(Scope.OPENID), stored.allowedScopes)
    }

    // --- helpers ---------------------------------------------------------------------------

    private fun client(id: String, scopes: Set<String>) = OAuthClient(
        clientId = ClientId(id),
        name = id,
        type = ClientType.PUBLIC,
        secretHash = null,
        secretRotatedAt = null,
        redirectUris = setOf("https://example.test/$id/callback"),
        allowedScopes = scopes,
        allowedGrantTypes = setOf(GrantType.AUTHORIZATION_CODE),
        skipConsent = false,
        audiences = setOf(id),
        enabled = true,
        createdAt = now,
        updatedAt = now,
    )

    private fun countScopes(): Int = queryOne("SELECT count(*) FROM oauth_scopes") { it.getInt(1) }

    private fun createdAtOf(name: String): Instant =
        queryOne("SELECT created_at FROM oauth_scopes WHERE name = '$name'") {
            it.getTimestamp(1).toInstant()
        }

    private fun <T> queryOne(sql: String, read: (java.sql.ResultSet) -> T): T =
        PostgresFixture.container.createConnection("").use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery(sql).use { rows ->
                    rows.next()
                    read(rows)
                }
            }
        }

    private fun execute(sql: String) {
        PostgresFixture.container.createConnection("").use { connection ->
            connection.createStatement().use { statement -> statement.execute(sql) }
        }
    }
}
