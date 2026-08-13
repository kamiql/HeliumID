package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.Consent
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.ConsentId
import dev.kamiql.helium.domain.common.RefreshTokenFamilyId
import dev.kamiql.helium.domain.common.RefreshTokenId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.common.SessionId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Principal
import dev.kamiql.helium.domain.repository.ClientRepository
import dev.kamiql.helium.domain.repository.ConsentRepository
import dev.kamiql.helium.domain.repository.Page
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.token.RefreshToken
import dev.kamiql.helium.domain.token.RefreshTokenFamily
import dev.kamiql.helium.flow.FlowContext
import dev.kamiql.helium.flow.FlowResult
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.port.TransactionManager
import java.time.Duration
import java.time.Instant

/**
 * Fakes for the authorized-applications suite.
 *
 * Separate from `TrustedDeviceFakes` because the two suites share almost nothing: that one needs
 * a transaction manager that simulates rollback, this one needs consents, clients and refresh
 * families. Only [RecordingOutbox] and [RecordingAudit] are borrowed from there.
 */

internal val APP_T0: Instant = Instant.parse("2026-01-01T12:00:00Z")

internal class InMemoryConsentRepository : ConsentRepository {

    private val stored = mutableListOf<Consent>()

    fun rows(): List<Consent> = stored.toList()

    override suspend fun find(userId: UserId, clientId: ClientId): Consent? =
        stored.firstOrNull { it.userId == userId && it.clientId == clientId && it.revokedAt == null }

    override suspend fun grant(consent: Consent): Consent {
        stored.removeAll { it.userId == consent.userId && it.clientId == consent.clientId }
        stored += consent
        return consent
    }

    /** Mirrors the SQL: only a live row is affected, so a second revoke reports `false`. */
    override suspend fun revoke(userId: UserId, clientId: ClientId, at: Instant): Boolean {
        val index = stored.indexOfFirst {
            it.userId == userId && it.clientId == clientId && it.revokedAt == null
        }
        if (index < 0) return false
        stored[index] = stored[index].copy(revokedAt = at)
        return true
    }

    override suspend fun listForUser(userId: UserId): List<Consent> =
        stored.filter { it.userId == userId && it.revokedAt == null }
}

internal class InMemoryRefreshTokenRepository : RefreshTokenRepository {

    private val families = mutableListOf<RefreshTokenFamily>()

    fun rows(): List<RefreshTokenFamily> = families.toList()

    fun seed(family: RefreshTokenFamily) {
        families += family
    }

    override suspend fun createFamily(family: RefreshTokenFamily): RefreshTokenFamily {
        families += family
        return family
    }

    override suspend fun findFamily(id: RefreshTokenFamilyId): RefreshTokenFamily? =
        families.firstOrNull { it.id == id }

    override suspend fun listActiveFamiliesForUser(
        userId: UserId,
        now: Instant,
    ): List<RefreshTokenFamily> =
        families.filter { it.userId == userId && it.isActive(now) }
            .sortedByDescending { it.createdAt }

    override suspend fun revokeFamiliesForUserAndClient(
        userId: UserId,
        clientId: ClientId,
        at: Instant,
    ): Int {
        // Matches the SQL predicate: revoked rows are skipped, expired-but-unrevoked ones are not.
        // Expiry is a read-time judgement, and leaving those rows unrevoked would let a second
        // call report work it did not do.
        val hits = families.withIndex().filter { (_, family) ->
            family.userId == userId && family.clientId == clientId && family.revokedAt == null
        }
        hits.forEach { (index, family) -> families[index] = family.copy(revokedAt = at) }
        return hits.size
    }

    override suspend fun revokeFamiliesForUser(userId: UserId, at: Instant): Int = unusedApp()
    override suspend fun revokeFamiliesForSession(sessionId: SessionId, at: Instant): Int = unusedApp()
    override suspend fun insertToken(token: RefreshToken): RefreshToken = unusedApp()
    override suspend fun findByHash(tokenHash: String): RefreshToken? = unusedApp()
    override suspend fun markUsed(tokenId: RefreshTokenId, at: Instant, replacedBy: RefreshTokenId): Boolean =
        unusedApp()

    override suspend fun revokeFamily(
        familyId: RefreshTokenFamilyId,
        at: Instant,
        reuseDetected: Boolean,
    ): Int = unusedApp()

    override suspend fun deleteExpired(before: Instant): Int = unusedApp()
}

/** Only the read side is exercised; client administration belongs to another suite. */
internal class StubClientRepository(
    private val clients: MutableMap<ClientId, OAuthClient> = mutableMapOf(),
    private val scopes: List<Scope> = Scope.STANDARD,
) : ClientRepository {

    fun register(clientId: String, name: String): ClientId {
        val id = ClientId(clientId)
        clients[id] = OAuthClient(
            clientId = id,
            name = name,
            type = ClientType.PUBLIC,
            secretHash = null,
            secretRotatedAt = null,
            redirectUris = setOf("https://app.example.test/callback"),
            allowedScopes = setOf("openid", "profile", "email"),
            allowedGrantTypes = setOf(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
            skipConsent = false,
            audiences = setOf("api"),
            enabled = true,
            createdAt = APP_T0,
            updatedAt = APP_T0,
        )
        return id
    }

    fun forget(clientId: ClientId) {
        clients.remove(clientId)
    }

    override suspend fun findById(clientId: ClientId): OAuthClient? = clients[clientId]

    override suspend fun listScopes(): List<Scope> = scopes

    override suspend fun list(limit: Int, offset: Long): Page<OAuthClient> = unusedApp()
    override suspend fun insert(client: OAuthClient): OAuthClient = unusedApp()
    override suspend fun update(client: OAuthClient): OAuthClient = unusedApp()
    override suspend fun updateSecret(clientId: ClientId, secretHash: String, at: Instant) = unusedApp()
    override suspend fun delete(clientId: ClientId): Boolean = unusedApp()
    override suspend fun findScope(name: String): Scope? = unusedApp()
    override suspend fun upsertScope(scope: Scope, at: Instant): Scope = unusedApp()
    override suspend fun deleteScope(name: String): Boolean = unusedApp()
    override suspend fun clientsUsingScope(name: String): Long = unusedApp()
}

/** Runs the block inline. Rollback behaviour is covered by the persistence suite, not here. */
internal class DirectTransactionManager : TransactionManager {
    override suspend fun <T> transaction(block: suspend () -> T): T = block()
    override suspend fun <T> requiresNew(block: suspend () -> T): T = block()
}

private fun unusedApp(): Nothing =
    error("this port is not exercised by the authorized-apps suite; a call here is a test defect")

// --- fixture --------------------------------------------------------------------------

/** Wires the real [AuthorizedAppService] and [AuthorizedAppFlows] onto the fakes above. */
internal class AuthorizedAppFixture {

    val consents = InMemoryConsentRepository()
    val refreshTokens = InMemoryRefreshTokenRepository()
    val clients = StubClientRepository()
    val outbox = RecordingOutbox()
    val audit = RecordingAudit()

    val service = AuthorizedAppService(consents, refreshTokens, clients)
    private val flows = AuthorizedAppFlows(consents, refreshTokens)
    private val runner = FlowRunner(DirectTransactionManager(), outbox, audit)

    fun context(
        userId: UserId?,
        now: Instant = APP_T0,
        permissions: Set<Permission> = setOf(Permission.ACCOUNT_SESSION_MANAGE),
    ): FlowContext = FlowContext(
        requestId = RequestId("req_authorized_apps"),
        actor = if (userId == null) {
            Principal.Anonymous
        } else {
            Principal.UserSession(
                userId = userId,
                sessionId = SessionId.random(),
                permissions = permissions,
                roles = setOf("USER"),
                authenticationMethods = setOf(AuthenticationMethod.PASSWORD),
                emailVerified = true,
            )
        },
        ipAddress = "203.0.113.10",
        userAgent = "test-agent",
        now = now,
    )

    suspend fun revoke(
        userId: UserId?,
        clientId: ClientId,
        now: Instant = APP_T0,
        permissions: Set<Permission> = setOf(Permission.ACCOUNT_SESSION_MANAGE),
    ): FlowResult<Unit> = runner.execute(
        flows.revokeAuthorization,
        RevokeAuthorizationCommand(clientId),
        context(userId, now, permissions),
    )

    /** Records a standing approval, as the authorization endpoint would. */
    suspend fun consent(userId: UserId, clientId: ClientId, scopes: Set<String>, at: Instant = APP_T0) {
        consents.grant(
            Consent(
                id = ConsentId.random(),
                userId = userId,
                clientId = clientId,
                grantedScopes = scopes,
                grantedAt = at,
                revokedAt = null,
            ),
        )
    }

    /** Records a refresh-token family, as the token endpoint would. */
    fun family(
        userId: UserId,
        clientId: ClientId,
        scopes: Set<String> = setOf("openid", "profile"),
        createdAt: Instant = APP_T0,
        expiresAt: Instant = createdAt.plus(Duration.ofDays(30)),
        revokedAt: Instant? = null,
        reuseDetectedAt: Instant? = null,
    ): RefreshTokenFamily = RefreshTokenFamily(
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
    ).also(refreshTokens::seed)
}
