package dev.kamiql.helium.app

import dev.kamiql.helium.api.SessionResponse
import dev.kamiql.helium.api.UpdateProfileRequest
import dev.kamiql.helium.api.UserResponse
import dev.kamiql.helium.app.support.heliumTest
import io.ktor.client.call.body
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What a signed-in person can see and change about their own account.
 *
 * The theme running through these is the authorization boundary rather than the happy path: each
 * of these routes derives its subject from the principal and never from the request, and the
 * cheapest way for that to break is for one of them to start reading an id out of a parameter.
 */
@Tag("integration")
class AccountSurfaceTest {

    @Test
    fun `the profile can be read and updated`() = heliumTest {
        val account = actors.user()

        val updated = http.put("/v1/me") {
            contentType(ContentType.Application.Json)
            setBody(UpdateProfileRequest(firstName = "Ada", lastName = "Lovelace"))
        }
        assertEquals(HttpStatusCode.OK, updated.status)

        val profile = http.get("/v1/me").body<UserResponse>()
        assertEquals("Ada", profile.firstName)
        assertEquals("Lovelace", profile.lastName)
        assertEquals(account.username, profile.username, "the update must not have renamed the account")
    }

    @Test
    fun `an anonymous caller sees nothing of an account`() = heliumTest {
        assertEquals(HttpStatusCode.Unauthorized, http.get("/v1/me").status)
        assertEquals(HttpStatusCode.Unauthorized, http.get("/v1/me/sessions").status)
        assertEquals(HttpStatusCode.Unauthorized, http.get("/v1/me/mfa").status)
        assertEquals(HttpStatusCode.Unauthorized, http.get("/v1/me/providers").status)
    }

    /** A fresh account has no second factor and no linked identity; both lists answer empty. */
    @Test
    fun `factors and linked providers start empty`() = heliumTest {
        actors.user()

        assertEquals(HttpStatusCode.OK, http.get("/v1/me/mfa").status)
        assertEquals("[]", http.get("/v1/me/mfa").body<String>())
        assertEquals("[]", http.get("/v1/me/providers").body<String>())
    }

    @Test
    fun `sessions list the current one and can be revoked individually`() = heliumTest {
        val account = actors.user()

        // A second sign-in from another client, so there is something to revoke that is not us.
        val other = actors.separateClient()
        actors.signIn(account, other)

        val sessions = http.get("/v1/me/sessions").body<List<SessionResponse>>()
        assertEquals(2, sessions.size, "both sign-ins should be listed")
        val current = assertNotNull(sessions.singleOrNull { it.current }, "exactly one session is current")
        val victim = sessions.single { !it.current }

        val revoked = http.delete("/v1/me/sessions/{sessionId}", "sessionId" to victim.id)
        assertEquals(HttpStatusCode.NoContent, revoked.status)

        assertEquals(
            HttpStatusCode.Unauthorized, other.get("/v1/me").status,
            "the revoked session must stop working immediately",
        )
        assertEquals(
            HttpStatusCode.OK, http.get("/v1/me").status,
            "revoking one session must not sign the caller out of their own",
        )
        assertTrue(current.id != victim.id)
    }

    /**
     * One account cannot revoke another's session.
     *
     * A session id is a server-generated UUID rather than a secret, so the only thing standing
     * between an attacker who has seen one and the account behind it is this ownership check.
     */
    @Test
    fun `a session belonging to somebody else cannot be revoked`() = heliumTest {
        val victimClient = actors.separateClient()
        val victim = actors.user(victimClient)
        val victimSession = victimClient.get("/v1/me/sessions").body<List<SessionResponse>>().single()

        actors.user() // the attacker, on the default client

        val response = http.delete("/v1/me/sessions/{sessionId}", "sessionId" to victimSession.id)
        assertEquals(HttpStatusCode.NotFound, response.status)

        assertEquals(
            HttpStatusCode.OK, victimClient.get("/v1/me").status,
            "the victim's session must have survived",
        )
        assertNotNull(victim)
    }

    /** A malformed id is answered like an unknown one, so the two cannot be told apart. */
    @Test
    fun `a malformed session id is not distinguishable from an unknown one`() = heliumTest {
        actors.user()

        val malformed = http.delete("/v1/me/sessions/{sessionId}", "sessionId" to "not-a-uuid")
        val unknown = http.delete(
            "/v1/me/sessions/{sessionId}",
            "sessionId" to "00000000-0000-0000-0000-000000000000",
        )

        assertEquals(HttpStatusCode.NotFound, malformed.status)
        assertEquals(HttpStatusCode.NotFound, unknown.status)
    }
}
