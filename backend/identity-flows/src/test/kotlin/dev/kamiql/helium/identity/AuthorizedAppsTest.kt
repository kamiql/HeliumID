package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.flow.FlowResult
import kotlinx.coroutines.test.runTest
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Which applications can reach my account, and how do I stop one of them?"
 *
 * The listing is assembled from two independent sources, so most of what can go wrong here is a
 * merge defect: an app that has access but is not shown, or one that is shown but has none. The
 * revocation half is about ownership and about not becoming an oracle for client ids.
 */
class AuthorizedAppsTest {

    private val demo = "demo-app"
    private val console = "helium-console"

    @Test
    fun `a consent and its live tokens collapse into one entry`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("openid", "profile"))
        fixture.family(user, clientId, createdAt = APP_T0.plus(Duration.ofDays(2)))

        val apps = fixture.service.list(user, APP_T0.plus(Duration.ofDays(3)))

        assertEquals(1, apps.size)
        val app = apps.single()
        assertEquals("Demo App", app.name)
        assertTrue(app.consented)
        assertEquals(1, app.activeGrants)
        // Access began with the consent, not with the newest token.
        assertEquals(APP_T0, app.authorizedAt)
        assertEquals(APP_T0.plus(Duration.ofDays(2)), app.lastAuthorizedAt)
    }

    @Test
    fun `a first-party client with no consent row is still listed`() = runTest {
        // The reason this list is built from both sources. `skipConsent` clients never produce a
        // consent row, and a "connected apps" screen that hides them is a comfortable lie.
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(console, "HeliumID Console")

        fixture.family(user, clientId, scopes = setOf("openid", "profile"))

        val app = fixture.service.list(user, APP_T0).single()

        assertEquals("HeliumID Console", app.name)
        assertFalse(app.consented)
        assertEquals(1, app.activeGrants)
    }

    @Test
    fun `a consent whose tokens have all expired is listed with no active grants`() = runTest {
        // It grants nothing today, but the next authorization request would sail past the consent
        // screen on the strength of it, so the owner has to be able to see and remove it.
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("profile"))
        fixture.family(user, clientId, expiresAt = APP_T0.plus(Duration.ofDays(1)))

        val app = fixture.service.list(user, APP_T0.plus(Duration.ofDays(2))).single()

        assertEquals(0, app.activeGrants)
        assertNull(app.lastAuthorizedAt)
    }

    @Test
    fun `revoked and reuse-detected families do not count as access`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.family(user, clientId, revokedAt = APP_T0)
        fixture.family(user, clientId, reuseDetectedAt = APP_T0)

        assertTrue(fixture.service.list(user, APP_T0).isEmpty())
    }

    @Test
    fun `implicit scopes are not presented as something the user agreed to`() = runTest {
        // `openid` is a protocol switch the consent screen never showed; listing it here would
        // claim the user approved something they were never asked about.
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("openid", "profile", "email"))

        val scopes = fixture.service.list(user, APP_T0).single().scopes

        assertEquals(listOf("email", "profile"), scopes.map { it.name })
        // The catalogue sentence, not the bare name — that is what the consent screen showed.
        assertEquals("See your name and username", scopes.first { it.name == "profile" }.description)
    }

    @Test
    fun `an unregistered scope falls back to its own name`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("workspace:read"))

        val scope = fixture.service.list(user, APP_T0).single().scopes.single()

        assertEquals("workspace:read", scope.name)
        assertEquals("workspace:read", scope.description)
    }

    @Test
    fun `scopes from live tokens are shown even when the consent is narrower`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("profile"))
        fixture.family(user, clientId, scopes = setOf("email"))

        val scopes = fixture.service.list(user, APP_T0).single().scopes.map { it.name }

        assertEquals(listOf("email", "profile"), scopes)
    }

    @Test
    fun `another user's authorizations are invisible`() = runTest {
        val fixture = AuthorizedAppFixture()
        val owner = UserId.random()
        val stranger = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(owner, clientId, setOf("profile"))
        fixture.family(owner, clientId)

        assertTrue(fixture.service.list(stranger, APP_T0).isEmpty())
    }

    @Test
    fun `the list is ordered by most recent activity`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val quiet = fixture.clients.register("quiet-app", "Quiet App")
        val busy = fixture.clients.register("busy-app", "Busy App")

        fixture.consent(user, quiet, setOf("profile"))
        fixture.consent(user, busy, setOf("profile"))
        fixture.family(user, busy, createdAt = APP_T0.plus(Duration.ofDays(5)))

        val names = fixture.service.list(user, APP_T0.plus(Duration.ofDays(6))).map { it.name }

        assertEquals(listOf("Busy App", "Quiet App"), names)
    }

    // --- revocation ---------------------------------------------------------------------

    @Test
    fun `revoking drops the consent and kills every live family`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("profile"))
        fixture.family(user, clientId)
        fixture.family(user, clientId, createdAt = APP_T0.plus(Duration.ofDays(1)))

        val now = APP_T0.plus(Duration.ofDays(2))
        assertIs<FlowResult.Success<Unit>>(fixture.revoke(user, clientId, now))

        // Both halves matter: consent alone would leave the tokens minting, tokens alone would
        // let the next authorization request skip the consent screen.
        assertTrue(fixture.service.list(user, now).isEmpty())
        assertTrue(fixture.consents.rows().all { it.revokedAt == now })
        assertTrue(fixture.refreshTokens.rows().all { it.revokedAt == now })
    }

    @Test
    fun `revoking one application leaves the others alone`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val revoked = fixture.clients.register(demo, "Demo App")
        val kept = fixture.clients.register(console, "HeliumID Console")

        fixture.family(user, revoked)
        fixture.family(user, kept)

        assertIs<FlowResult.Success<Unit>>(fixture.revoke(user, revoked))

        assertEquals(listOf("HeliumID Console"), fixture.service.list(user, APP_T0).map { it.name })
    }

    @Test
    fun `revoking somebody else's authorization reports not found and changes nothing`() = runTest {
        val fixture = AuthorizedAppFixture()
        val owner = UserId.random()
        val stranger = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(owner, clientId, setOf("profile"))
        fixture.family(owner, clientId)

        val result = assertIs<FlowResult.Failure>(fixture.revoke(stranger, clientId))
        assertEquals(AuthError.NotFound, result.error)
        assertEquals(1, fixture.service.list(owner, APP_T0).single().activeGrants)
    }

    @Test
    fun `an unknown client id is indistinguishable from one that was never granted`() = runTest {
        // Both answer NotFound. Anything else turns this endpoint into an oracle for which client
        // ids are registered.
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        fixture.clients.register(demo, "Demo App")

        val unknown = assertIs<FlowResult.Failure>(fixture.revoke(user, ClientId("no-such-client")))
        val ungranted = assertIs<FlowResult.Failure>(fixture.revoke(user, ClientId(demo)))

        assertEquals(AuthError.NotFound, unknown.error)
        assertEquals(AuthError.NotFound, ungranted.error)
    }

    @Test
    fun `a second revoke reports not found`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("profile"))
        fixture.family(user, clientId)

        assertIs<FlowResult.Success<Unit>>(fixture.revoke(user, clientId))
        val second = assertIs<FlowResult.Failure>(fixture.revoke(user, clientId))

        assertEquals(AuthError.NotFound, second.error)
    }

    @Test
    fun `a standing consent with no live tokens can still be revoked`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("profile"))

        assertIs<FlowResult.Success<Unit>>(fixture.revoke(user, clientId))
        assertTrue(fixture.service.list(user, APP_T0).isEmpty())
    }

    @Test
    fun `revoking emits an audited event naming the client`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")

        fixture.consent(user, clientId, setOf("profile"))
        fixture.family(user, clientId)

        assertIs<FlowResult.Success<Unit>>(fixture.revoke(user, clientId))

        val event = assertIs<DomainEvent.AuthorizationRevoked>(fixture.outbox.published.single())
        assertEquals(user, event.userId)
        assertEquals(clientId, event.clientId)
        assertEquals(1, event.revokedGrants)
        assertEquals("account.authorization.revoke", fixture.audit.entries.single().eventType)
    }

    @Test
    fun `a failed revoke leaves no event behind`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        fixture.clients.register(demo, "Demo App")

        assertIs<FlowResult.Failure>(fixture.revoke(user, ClientId(demo)))

        assertTrue(fixture.outbox.published.isEmpty())
    }

    @Test
    fun `an anonymous caller cannot revoke`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")
        fixture.consent(user, clientId, setOf("profile"))

        val result = assertIs<FlowResult.Failure>(fixture.revoke(userId = null, clientId = clientId))

        assertEquals(AuthError.AuthenticationRequired, result.error)
        assertEquals(1, fixture.consents.rows().count { it.revokedAt == null })
    }

    @Test
    fun `a caller without session management cannot revoke`() = runTest {
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")
        fixture.consent(user, clientId, setOf("profile"))

        val result = assertIs<FlowResult.Failure>(
            fixture.revoke(user, clientId, permissions = setOf(Permission.ACCOUNT_MFA_MANAGE)),
        )

        assertIs<AuthError.Forbidden>(result.error)
        assertEquals(1, fixture.consents.rows().count { it.revokedAt == null })
    }

    @Test
    fun `a client that no longer exists is dropped from the listing`() = runTest {
        // Consents and families cascade with the client row, so this is a guard against a stale
        // row rather than an expected state — but a listing that cannot name the app is useless.
        val fixture = AuthorizedAppFixture()
        val user = UserId.random()
        val clientId = fixture.clients.register(demo, "Demo App")
        fixture.consent(user, clientId, setOf("profile"))
        fixture.clients.forget(clientId)

        assertTrue(fixture.service.list(user, APP_T0).isEmpty())
    }
}
