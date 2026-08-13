package dev.kamiql.helium.app

import dev.kamiql.helium.api.AuthorizedAppResponse
import dev.kamiql.helium.api.ClientSecretResponse
import dev.kamiql.helium.api.ConsentPromptResponse
import dev.kamiql.helium.api.RegisterClientRequest
import dev.kamiql.helium.api.TokenEndpointResponse
import dev.kamiql.helium.app.support.HeliumTestClient
import dev.kamiql.helium.app.support.HeliumTestScope
import dev.kamiql.helium.app.support.heliumTest
import io.ktor.client.call.body
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.contentType
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Which applications can reach my account", from the grant that creates one to the revocation
 * that ends it.
 *
 * The listing is assembled from two different tables and the revocation writes to both, so this
 * is a feature that only exists once the whole stack is assembled: a consent row is created by
 * the authorization endpoint, a refresh-token family by the token endpoint, and neither is
 * visible to a test that fakes the other. Getting there means driving a genuine authorization
 * code flow with PKCE, which is the point — the grant under test is a real one.
 */
@Tag("integration")
class AuthorizedAppsE2eTest {

    @Test
    fun `a granted client appears, and revoking it withdraws consent and kills its tokens`() = heliumTest {
        val admin = actors.separateClient()
        actors.admin(admin)
        registerClient(admin, CLIENT_ID)

        val user = actors.user()

        // --- the consent screen is shown before anything is granted -----------------
        val prompt = authorize(consent = false)
        assertEquals(HttpStatusCode.OK, prompt.status, "a third-party client must be consented to")
        val prompted = prompt.body<ConsentPromptResponse>()
        assertEquals(CLIENT_ID, prompted.clientId)

        assertTrue(
            listAuthorizations().isEmpty(),
            "being asked for consent must not be the same as having granted it",
        )

        // --- grant, and exchange the code -------------------------------------------
        val granted = authorize(consent = true)
        assertEquals(HttpStatusCode.Found, granted.status)
        val code = granted.redirectParameter("code")
        assertEquals(STATE, granted.redirectParameter("state"), "state must be echoed unchanged")

        val tokens = exchangeCode(code).body<TokenEndpointResponse>()
        assertTrue(tokens.accessToken.isNotBlank())
        val refreshToken = assertNotNull(tokens.refreshToken, "offline_access must yield a refresh token")

        // The access token works, which is what makes revocation meaningful.
        val userinfo = http.get("/userinfo") { header(HttpHeaders.Authorization, "Bearer ${tokens.accessToken}") }
        assertEquals(HttpStatusCode.OK, userinfo.status)

        // --- the grant is visible to its owner ---------------------------------------
        val listed = listAuthorizations().single()
        assertEquals(CLIENT_ID, listed.clientId)
        assertTrue(listed.consented, "an explicitly consented client must not look first-party")
        assertEquals(1, listed.activeGrants, "the refresh-token family should be counted")
        assertNotNull(listed.lastAuthorizedAt)

        // --- and only to its owner ----------------------------------------------------
        val stranger = actors.separateClient()
        actors.user(stranger)
        assertTrue(
            stranger.get("/v1/me/authorizations").body<List<AuthorizedAppResponse>>().isEmpty(),
            "one account's grants must never appear in another's list",
        )

        // --- revoke ---------------------------------------------------------------------
        val revoked = http.delete("/v1/me/authorizations/{clientId}", "clientId" to CLIENT_ID)
        assertEquals(HttpStatusCode.NoContent, revoked.status)

        assertTrue(listAuthorizations().isEmpty(), "a revoked grant must disappear from the listing")

        val refreshed = tokenRequest(
            Parameters.build {
                append("grant_type", "refresh_token")
                append("refresh_token", refreshToken)
                append("client_id", CLIENT_ID)
            },
        )
        assertEquals(
            HttpStatusCode.BadRequest, refreshed.status,
            "revocation must kill the refresh-token family, not only the consent row",
        )

        // The consent is gone too: the client has to ask again rather than sail through.
        assertEquals(
            HttpStatusCode.OK, authorize(consent = false).status,
            "the consent screen must return; a standing approval would survive the revocation",
        )

        assertNotNull(user)
    }

    /**
     * A first-party client is listed even though it never produced a consent row.
     *
     * This is the case the listing exists to catch. `skip_consent` means the authorization
     * endpoint writes nothing to `consents`, so a listing built from that table alone would show
     * the user nothing while the client held a live refresh token for their account.
     */
    @Test
    fun `a skip-consent client is still listed once it holds a token`() = heliumTest {
        val admin = actors.separateClient()
        actors.admin(admin)
        registerClient(admin, FIRST_PARTY_ID, skipConsent = true)

        actors.user()

        val granted = authorize(clientId = FIRST_PARTY_ID, consent = false)
        assertEquals(
            HttpStatusCode.Found, granted.status,
            "a skip-consent client must not be prompted",
        )
        exchangeCode(granted.redirectParameter("code"), clientId = FIRST_PARTY_ID)

        val listed = listAuthorizations().single()
        assertEquals(FIRST_PARTY_ID, listed.clientId)
        assertTrue(!listed.consented, "there is no consent row behind this one, and it should say so")
        assertEquals(1, listed.activeGrants)

        assertEquals(
            HttpStatusCode.NoContent,
            http.delete("/v1/me/authorizations/{clientId}", "clientId" to FIRST_PARTY_ID).status,
            "a first-party client must be revocable even with nothing in `consents`",
        )
    }

    /**
     * Revoking something that was never granted answers `404`, like everything else.
     *
     * Otherwise the endpoint sorts registered client ids from unregistered ones for any
     * authenticated caller — an enumeration oracle over the client registry.
     */
    @Test
    fun `revoking an unknown or ungranted client is indistinguishable`() = heliumTest {
        val admin = actors.separateClient()
        actors.admin(admin)
        registerClient(admin, CLIENT_ID)

        actors.user()

        val unregistered = http.delete("/v1/me/authorizations/{clientId}", "clientId" to "no-such-client")
        val registeredButUngranted = http.delete("/v1/me/authorizations/{clientId}", "clientId" to CLIENT_ID)

        assertEquals(HttpStatusCode.NotFound, unregistered.status)
        assertEquals(HttpStatusCode.NotFound, registeredButUngranted.status)
    }

    @Test
    fun `the listing requires authentication`() = heliumTest {
        assertEquals(HttpStatusCode.Unauthorized, http.get("/v1/me/authorizations").status)
    }

    // --- helpers ------------------------------------------------------------------------

    private suspend fun HeliumTestScope.listAuthorizations(): List<AuthorizedAppResponse> =
        http.get("/v1/me/authorizations").body()

    private suspend fun HeliumTestScope.registerClient(
        admin: HeliumTestClient,
        clientId: String,
        skipConsent: Boolean = false,
    ): ClientSecretResponse {
        val response = admin.post("/v1/admin/clients") {
            contentType(ContentType.Application.Json)
            setBody(
                RegisterClientRequest(
                    clientId = clientId,
                    name = "Test Client $clientId",
                    type = "PUBLIC",
                    redirectUris = listOf(REDIRECT_URI),
                    scopes = listOf("openid", "profile", "email", "offline_access"),
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    skipConsent = skipConsent,
                ),
            )
        }
        assertEquals(HttpStatusCode.Created, response.status, "client registration was refused")
        return response.body()
    }

    private suspend fun HeliumTestScope.authorize(
        clientId: String = CLIENT_ID,
        consent: Boolean,
    ): HttpResponse = http.get("/oauth2/authorize") {
        parameter("client_id", clientId)
        parameter("response_type", "code")
        parameter("redirect_uri", REDIRECT_URI)
        parameter("scope", "openid profile email offline_access")
        parameter("state", STATE)
        parameter("nonce", NONCE)
        parameter("code_challenge", CHALLENGE)
        parameter("code_challenge_method", "S256")
        if (consent) parameter("consent", "granted")
    }

    private suspend fun HeliumTestScope.exchangeCode(
        code: String,
        clientId: String = CLIENT_ID,
    ): HttpResponse {
        val response = tokenRequest(
            Parameters.build {
                append("grant_type", "authorization_code")
                append("code", code)
                append("redirect_uri", REDIRECT_URI)
                append("code_verifier", VERIFIER)
                append("client_id", clientId)
            },
        )
        assertEquals(HttpStatusCode.OK, response.status, "code exchange was refused")
        return response
    }

    private suspend fun HeliumTestScope.tokenRequest(form: Parameters): HttpResponse =
        http.post("/oauth2/token") { setBody(FormDataContent(form)) }

    /** Pulls one query parameter out of a `Location` header, failing loudly if the shape is off. */
    private fun HttpResponse.redirectParameter(name: String): String {
        val location = assertNotNull(headers[HttpHeaders.Location], "no Location header on a redirect")
        assertNull(
            Url(location).parameters["error"],
            "the authorization endpoint returned an error redirect: $location",
        )
        return assertNotNull(Url(location).parameters[name], "no '$name' in $location")
    }

    private companion object {
        const val CLIENT_ID = "e2e-third-party"
        const val FIRST_PARTY_ID = "e2e-first-party"
        const val REDIRECT_URI = "http://localhost/callback"
        const val STATE = "state-value-not-guessable"
        const val NONCE = "nonce-value-not-guessable"

        /** A fixed PKCE pair, so a failure reproduces exactly. */
        const val VERIFIER = "verifier-that-is-long-enough-to-satisfy-rfc7636-0123456789"
        val CHALLENGE: String = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(VERIFIER.toByteArray(Charsets.US_ASCII)),
        )
    }
}
