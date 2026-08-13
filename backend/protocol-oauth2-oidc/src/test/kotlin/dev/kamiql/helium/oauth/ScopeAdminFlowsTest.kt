package dev.kamiql.helium.oauth

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.TokenHasher
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.repository.ClientRepository
import dev.kamiql.helium.domain.repository.Page
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.session.Session
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.FlowResult
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.port.AuditEntry
import dev.kamiql.helium.flow.port.AuditPort
import dev.kamiql.helium.flow.port.OutboxContext
import dev.kamiql.helium.flow.port.OutboxPort
import dev.kamiql.helium.flow.port.TransactionManager
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The scope catalogue's write path.
 *
 * These flows exist so a deployment can define its own `resource:action` scopes; before them the
 * catalogue was whatever `V2__reference_data.sql` seeded and nothing else. What is worth testing
 * is not that a row is written — it is the four refusals, because each one guards against a
 * change that would break something far away from the endpoint that made it.
 *
 * The flows are real. Only the adapters underneath are fakes: the policy under test lives in the
 * flow declarations, and stubbing those out would test the fixture.
 */
class ScopeAdminFlowsTest {

    // --- upsert ---------------------------------------------------------------------

    @Test
    fun `a new scope is registered and reported back`(): Unit = runTest {
        val fixture = ScopeFixture()

        val result = fixture.upsert("workspace:read", "See your documents")

        val scope = assertIs<FlowResult.Success<Scope>>(result).value
        assertEquals("workspace:read", scope.name)
        assertEquals("See your documents", scope.description)
        assertFalseFlag(scope.implicit)
        // Nothing created through the API is ever built in — that flag belongs to the migration.
        assertFalseFlag(scope.builtIn)
        assertEquals(scope, fixture.clients.scopes["workspace:read"])
    }

    @Test
    fun `upserting an existing scope replaces its description`(): Unit = runTest {
        val fixture = ScopeFixture()
        fixture.upsert("workspace:read", "See your documents")

        val result = fixture.upsert("workspace:read", "Read documents you can access")

        val scope = assertIs<FlowResult.Success<Scope>>(result).value
        assertEquals("Read documents you can access", scope.description)
        assertEquals(1, fixture.clients.scopes.size)
    }

    /**
     * `openid` decides whether an ID token is issued at all and whether `/userinfo` answers.
     * Rewording it would change what users think they agreed to; making it non-implicit would put
     * it on the consent screen as a refusable choice it is not.
     */
    @Test
    fun `a built-in scope cannot be edited`(): Unit = runTest {
        val fixture = ScopeFixture()
        fixture.clients.seedBuiltIns()

        val result = fixture.upsert(Scope.OPENID, "Something else entirely")

        assertIs<AuthError.Conflict>(assertIs<FlowResult.Failure>(result).error)
        assertEquals("Confirm your identity", fixture.clients.scopes[Scope.OPENID]?.description)
    }

    /**
     * The `scope` request parameter and the `scope` claim are both space-delimited, so a name
     * containing a space would silently become two scopes on the wire.
     */
    @Test
    fun `a name with whitespace is rejected`(): Unit = runTest {
        val fixture = ScopeFixture()

        val result = fixture.upsert("workspace read", "See your documents")

        val error = assertIs<AuthError.ValidationFailed>(assertIs<FlowResult.Failure>(result).error)
        assertContains(error.fields.keys,"name")
        assertTrue(fixture.clients.scopes.isEmpty())
    }

    @Test
    fun `uppercase and overlong names are rejected`(): Unit = runTest {
        val fixture = ScopeFixture()

        assertIs<FlowResult.Failure>(fixture.upsert("Workspace:Read", "See your documents"))
        assertIs<FlowResult.Failure>(fixture.upsert("ab", "Too short"))
        assertIs<FlowResult.Failure>(fixture.upsert("w".repeat(65), "Too long"))
        assertTrue(fixture.clients.scopes.isEmpty())
    }

    /** The description is rendered verbatim on the consent screen, so an empty one is a defect. */
    @Test
    fun `a blank description is rejected`(): Unit = runTest {
        val fixture = ScopeFixture()

        val result = fixture.upsert("workspace:read", "   ")

        val error = assertIs<AuthError.ValidationFailed>(assertIs<FlowResult.Failure>(result).error)
        assertContains(error.fields.keys,"description")
    }

    // --- delete ---------------------------------------------------------------------

    @Test
    fun `an unused scope is deleted`(): Unit = runTest {
        val fixture = ScopeFixture()
        fixture.upsert("workspace:read", "See your documents")

        assertIs<FlowResult.Success<Unit>>(fixture.delete("workspace:read"))
        assertTrue(fixture.clients.scopes.isEmpty())
    }

    /**
     * The most important refusal here. `oauth_client_scopes.scope` cascades on delete, so without
     * this check the scope would vanish from every client that lists it, with no error at the
     * time and an `invalid_scope` on some authorization request much later.
     */
    @Test
    fun `a scope still used by a client cannot be deleted`(): Unit = runTest {
        val fixture = ScopeFixture()
        fixture.upsert("workspace:read", "See your documents")
        fixture.clients.seedClient("demo", scopes = setOf("workspace:read"))

        val result = fixture.delete("workspace:read")

        assertIs<AuthError.Conflict>(assertIs<FlowResult.Failure>(result).error)
        assertNotNull(fixture.clients.scopes["workspace:read"])
    }

    @Test
    fun `a built-in scope cannot be deleted`(): Unit = runTest {
        val fixture = ScopeFixture()
        fixture.clients.seedBuiltIns()

        val result = fixture.delete(Scope.OPENID)

        assertIs<AuthError.Conflict>(assertIs<FlowResult.Failure>(result).error)
        assertNotNull(fixture.clients.scopes[Scope.OPENID])
    }

    @Test
    fun `deleting an unknown scope is a not-found`(): Unit = runTest {
        val fixture = ScopeFixture()

        val result = fixture.delete("workspace:read")

        assertIs<AuthError.NotFound>(assertIs<FlowResult.Failure>(result).error)
    }

    // --- who may call these ----------------------------------------------------------

    @Test
    fun `an anonymous caller is asked to authenticate`(): Unit = runTest {
        val fixture = ScopeFixture()

        val result = fixture.upsert("workspace:read", "See your documents", actor = Principal.Anonymous)

        assertIs<AuthError.AuthenticationRequired>(assertIs<FlowResult.Failure>(result).error)
        assertTrue(fixture.clients.scopes.isEmpty())
    }

    @Test
    fun `a signed-in user without the permission is forbidden`(): Unit = runTest {
        val fixture = ScopeFixture()

        val result = fixture.upsert(
            "workspace:read",
            "See your documents",
            actor = fixture.session(permissions = emptySet()),
        )

        assertIs<AuthError.Forbidden>(assertIs<FlowResult.Failure>(result).error)
        assertTrue(fixture.clients.scopes.isEmpty())
    }

    /**
     * A stale session must step up first. This is also what stops the whole surface from being
     * reachable with a bearer token: `ReauthenticatedWithin` rejects any principal that is not a
     * `UserSession`, so a third-party access token can never define scopes.
     */
    @Test
    fun `a session that authenticated too long ago must reauthenticate`(): Unit = runTest {
        val fixture = ScopeFixture(authenticatedAt = T0.minus(Duration.ofHours(2)))

        val result = fixture.upsert("workspace:read", "See your documents")

        assertIs<AuthError.ReauthenticationRequired>(assertIs<FlowResult.Failure>(result).error)
        assertTrue(fixture.clients.scopes.isEmpty())
    }

    @Test
    fun `a bearer token can never define scopes`(): Unit = runTest {
        val fixture = ScopeFixture()

        val result = fixture.upsert(
            "workspace:read",
            "See your documents",
            actor = Principal.TokenBearer(
                userId = ADMIN_USER,
                clientId = ClientId("some-app"),
                scopes = emptySet(),
                // Full administrator rights, and still refused: the requirement is about how
                // recently a human proved themselves, which a token cannot answer.
                permissions = Permission.ALL.toSet(),
                authenticationMethods = setOf(AuthenticationMethod.PASSWORD),
            ),
        )

        assertIs<AuthError.ReauthenticationRequired>(assertIs<FlowResult.Failure>(result).error)
    }

    // --- audit ------------------------------------------------------------------------

    @Test
    fun `both writes emit a domain event naming the scope`(): Unit = runTest {
        val fixture = ScopeFixture()

        fixture.upsert("workspace:read", "See your documents")
        fixture.delete("workspace:read")

        val upserted = fixture.outbox.published.filterIsInstance<DomainEvent.ScopeUpserted>().single()
        assertEquals("workspace:read", upserted.scope)
        assertEquals(ADMIN_USER, upserted.actorUserId)

        val deleted = fixture.outbox.published.filterIsInstance<DomainEvent.ScopeDeleted>().single()
        assertEquals("workspace:read", deleted.scope)
    }

    @Test
    fun `a refused write emits nothing`(): Unit = runTest {
        val fixture = ScopeFixture()

        fixture.upsert("workspace read", "See your documents")

        assertTrue(fixture.outbox.published.isEmpty())
    }

    private fun assertFalseFlag(value: Boolean) = assertEquals(false, value)
}

// --- fixture --------------------------------------------------------------------------

private val T0: Instant = Instant.parse("2026-08-13T10:00:00Z")
private val ADMIN_USER: UserId = UserId.random()
private val ADMIN_SESSION: SessionId = SessionId.random()

/**
 * The parts of [ClientRepository] the scope flows touch, in memory.
 *
 * `upsertScope` mirrors the SQL exactly where it matters: `builtIn` and `createdAt` survive an
 * update. A fake that let those be overwritten would hide the very regression the real
 * `onUpdateExclude` exists to prevent.
 */
private class InMemoryClientRepository : ClientRepository {

    val scopes = linkedMapOf<String, Scope>()
    private val clients = linkedMapOf<String, OAuthClient>()
    private val scopeCreatedAt = mutableMapOf<String, Instant>()

    fun seedBuiltIns() {
        Scope.STANDARD.forEach { scopes[it.name] = it }
    }

    fun seedClient(clientId: String, scopes: Set<String>) {
        clients[clientId] = OAuthClient(
            clientId = ClientId(clientId),
            name = clientId,
            type = ClientType.PUBLIC,
            secretHash = null,
            secretRotatedAt = null,
            redirectUris = setOf("https://example.test/callback"),
            allowedScopes = scopes,
            allowedGrantTypes = setOf(GrantType.AUTHORIZATION_CODE),
            skipConsent = false,
            audiences = setOf(clientId),
            enabled = true,
            createdAt = T0,
            updatedAt = T0,
        )
    }

    override suspend fun listScopes(): List<Scope> = scopes.values.toList()

    override suspend fun findScope(name: String): Scope? = scopes[name]

    override suspend fun upsertScope(scope: Scope, at: Instant): Scope {
        val existing = scopes[scope.name]
        val stored = scope.copy(builtIn = existing?.builtIn ?: scope.builtIn)
        scopes[scope.name] = stored
        scopeCreatedAt.putIfAbsent(scope.name, at)
        return stored
    }

    override suspend fun deleteScope(name: String): Boolean = scopes.remove(name) != null

    override suspend fun clientsUsingScope(name: String): Long =
        clients.values.count { name in it.allowedScopes }.toLong()

    override suspend fun findById(clientId: ClientId): OAuthClient? = clients[clientId.value]

    override suspend fun list(limit: Int, offset: Long): Page<OAuthClient> =
        Page(clients.values.toList(), clients.size.toLong(), limit, offset)

    override suspend fun insert(client: OAuthClient): OAuthClient =
        client.also { clients[it.clientId.value] = it }

    override suspend fun update(client: OAuthClient): OAuthClient =
        client.also { clients[it.clientId.value] = it }

    override suspend fun updateSecret(clientId: ClientId, secretHash: String, at: Instant) = Unit

    override suspend fun delete(clientId: ClientId): Boolean = clients.remove(clientId.value) != null
}

private class RecordingOutbox : OutboxPort {
    val published = mutableListOf<DomainEvent>()

    override suspend fun publish(events: List<DomainEvent>, context: OutboxContext) {
        published += events
    }
}

private class RecordingAudit : AuditPort {
    val entries = mutableListOf<AuditEntry>()

    override suspend fun record(entry: AuditEntry) {
        entries += entry
    }
}

/** Runs the body inline; the scope flows have nothing to unwind that the fakes model. */
private object DirectTransactionManager : TransactionManager {
    override suspend fun <T> transaction(block: suspend () -> T): T = block()
    override suspend fun <T> requiresNew(block: suspend () -> T): T = block()
}

private class ScopeFixture(authenticatedAt: Instant = T0) {

    val clients = InMemoryClientRepository()
    val outbox = RecordingOutbox()
    val audit = RecordingAudit()

    private val sessions = mockk<SessionRepository>().also { repository ->
        coEvery { repository.findById(ADMIN_SESSION) } returns Session(
            id = ADMIN_SESSION,
            userId = ADMIN_USER,
            clientId = null,
            createdAt = authenticatedAt,
            lastSeenAt = T0,
            idleExpiresAt = T0.plus(Duration.ofHours(12)),
            absoluteExpiresAt = T0.plus(Duration.ofDays(7)),
            revokedAt = null,
            authenticatedAt = authenticatedAt,
            authenticationMethods = setOf(AuthenticationMethod.PASSWORD),
            ipHash = null,
            userAgentHash = null,
            deviceLabel = null,
        )
    }

    private val flows = ClientAdminFlows(
        clients = clients,
        users = mockk<UserRepository>(),
        sessions = sessions,
        tokenHasher = mockk<TokenHasher>(),
        random = mockk<RandomSource>(),
        allowInsecureRedirects = false,
    )

    private val runner = FlowRunner(DirectTransactionManager, outbox, audit)

    fun session(permissions: Set<Permission> = setOf(Permission.ADMIN_CLIENT_WRITE)): Principal =
        Principal.UserSession(
            userId = ADMIN_USER,
            sessionId = ADMIN_SESSION,
            permissions = permissions,
            roles = emptySet(),
            authenticationMethods = setOf(AuthenticationMethod.PASSWORD),
            emailVerified = true,
        )

    private fun context(actor: Principal) = FlowContext(
        requestId = RequestId("req_scope_admin"),
        actor = actor,
        now = T0,
    )

    suspend fun upsert(
        name: String,
        description: String,
        implicit: Boolean = false,
        actor: Principal = session(),
    ): FlowResult<Scope> = runner.execute(
        flow = flows.upsertScope,
        command = UpsertScopeCommand(name, description, implicit),
        context = context(actor),
    )

    suspend fun delete(name: String, actor: Principal = session()): FlowResult<Unit> = runner.execute(
        flow = flows.deleteScope,
        command = DeleteScopeCommand(name),
        context = context(actor),
    )
}
