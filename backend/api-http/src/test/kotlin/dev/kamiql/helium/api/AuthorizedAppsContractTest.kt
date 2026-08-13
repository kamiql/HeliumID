package dev.kamiql.helium.api

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.identity.AuthorizedApp
import dev.kamiql.helium.identity.AuthorizedScope
import kotlinx.serialization.json.Json
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The wire shape of `/v1/me/authorizations`.
 *
 * The account UI and any other client branch on these keys, so a rename is a silent break. The
 * negative half matters just as much: this response is about *who can reach my account*, and no
 * token material, secret or redirect URI has any business in it.
 */
class AuthorizedAppsContractTest {

    /** The same configuration `installHeliumPlugins` gives ContentNegotiation. */
    private val json = Json {
        explicitNulls = false
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val authorizedAt = Instant.parse("2026-08-01T09:00:00Z")
    private val lastAuthorizedAt = Instant.parse("2026-08-12T10:15:00Z")

    private fun app(
        lastAuthorizedAt: Instant? = this.lastAuthorizedAt,
        activeGrants: Int = 2,
        consented: Boolean = true,
    ) = AuthorizedApp(
        clientId = ClientId("demo-app"),
        name = "Demo App",
        scopes = listOf(AuthorizedScope("profile", "See your name and username")),
        authorizedAt = authorizedAt,
        lastAuthorizedAt = lastAuthorizedAt,
        activeGrants = activeGrants,
        consented = consented,
    )

    @Test
    fun `field names are snake case and timestamps are ISO-8601`() {
        val encoded = json.encodeToString(app().toResponse())

        assertTrue(encoded.contains("\"client_id\":\"demo-app\""), encoded)
        assertTrue(encoded.contains("\"name\":\"Demo App\""), encoded)
        assertTrue(encoded.contains("\"authorized_at\":\"2026-08-01T09:00:00Z\""), encoded)
        assertTrue(encoded.contains("\"last_authorized_at\":\"2026-08-12T10:15:00Z\""), encoded)
        assertTrue(encoded.contains("\"active_grants\":2"), encoded)
        assertTrue(encoded.contains("\"consented\":true"), encoded)
    }

    @Test
    fun `a scope carries the sentence the consent screen showed`() {
        // The bare name only means something to developers; the description is what the user was
        // actually asked to agree to, so it has to survive the mapping.
        val scope = app().toResponse().scopes.single()

        assertEquals("profile", scope.name)
        assertEquals("See your name and username", scope.description)
    }

    @Test
    fun `an app with no live tokens omits last_authorized_at rather than inventing one`() {
        // `explicitNulls = false` drops the key entirely; clients must treat absent as "never".
        val encoded = json.encodeToString(app(lastAuthorizedAt = null, activeGrants = 0).toResponse())

        assertFalse(encoded.contains("last_authorized_at"), encoded)
        assertTrue(encoded.contains("\"active_grants\":0"), encoded)
    }

    @Test
    fun `a first-party client is marked rather than hidden`() {
        val encoded = json.encodeToString(app(consented = false).toResponse())

        assertTrue(encoded.contains("\"consented\":false"), encoded)
    }

    @Test
    fun `the response carries nothing but identity and consent`() {
        // A client row also holds a secret hash, redirect URIs, grant types and audiences. None
        // of them belong in an endpoint every signed-in browser can call.
        val fields = json.encodeToString(app().toResponse())

        listOf("secret", "redirect", "grant_type", "audience", "token").forEach { forbidden ->
            assertFalse(fields.contains(forbidden, ignoreCase = true), "leaked $forbidden: $fields")
        }
    }
}
