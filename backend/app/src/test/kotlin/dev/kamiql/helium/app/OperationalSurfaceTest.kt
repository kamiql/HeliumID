package dev.kamiql.helium.app

import dev.kamiql.helium.app.support.heliumTest
import io.ktor.client.call.body
import io.ktor.http.HttpStatusCode
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The endpoints nobody signs in to reach: probes, metrics and OIDC discovery.
 *
 * Unauthenticated by necessity, which makes what they *do not* say as important as what they do.
 * A probe that names the failing dependency and a discovery document that advertises an endpoint
 * that does not exist are both reconnaissance, and both are cheap to introduce by accident.
 */
@Tag("integration")
class OperationalSurfaceTest {

    @Test
    fun `liveness answers without naming anything`() = heliumTest {
        val response = http.get("/health")

        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.body<String>()
        assertFalse(
            listOf("postgres", "jdbc", "redis", "password", "exception").any {
                body.contains(it, ignoreCase = true)
            },
            "the liveness probe must not describe the deployment: $body",
        )
    }

    @Test
    fun `readiness answers once the database does`() = heliumTest {
        assertEquals(HttpStatusCode.OK, http.get("/health/ready").status)
    }

    @Test
    fun `metrics are scrapeable and carry the flow counters`() = heliumTest {
        // Something to count, so the assertion is about the wiring rather than an empty registry.
        actors.user()

        val response = http.get("/metrics")
        assertEquals(HttpStatusCode.OK, response.status)

        val body = response.body<String>()
        assertTrue(body.contains("helium_flow"), "the flow engine's counters must reach the registry")
        assertFalse(
            body.contains("@helium.test"),
            "an email address in a metric label is exactly what MetricNames.ALLOWED_LABELS exists to stop",
        )
    }

    /**
     * Discovery must describe *this* server.
     *
     * The issuer is the value every relying party pins, and the endpoints are what they will
     * actually call — a document generated from a template rather than from configuration is a
     * fleet of clients pointed somewhere else.
     */
    @Test
    fun `discovery advertises this issuer and its real endpoints`() = heliumTest {
        val response = http.get("/.well-known/openid-configuration")
        assertEquals(HttpStatusCode.OK, response.status)

        val body = response.body<String>()
        assertTrue(body.contains("\"issuer\":\"${dev.kamiql.helium.app.support.HeliumTestApp.ISSUER}\""))
        assertTrue(body.contains("/oauth2/authorize"))
        assertTrue(body.contains("/oauth2/token"))
        assertTrue(body.contains("/.well-known/jwks.json"))
        assertTrue(body.contains("S256"), "PKCE S256 support must be advertised")
    }

    @Test
    fun `jwks publishes a public key and no private material`() = heliumTest {
        val body = http.get("/.well-known/jwks.json").body<String>()

        assertTrue(body.contains("\"kty\":\"EC\""), "an EC verification key should be published")
        assertTrue(body.contains("\"crv\":\"P-256\""))
        assertFalse(body.contains("\"d\":"), "a JWKS carrying the private scalar would leak the signing key")
    }

    /** No provider is configured in the test graph, so the list is honestly empty. */
    @Test
    fun `the provider list reflects configuration`() = heliumTest {
        val response = http.get("/v1/auth/providers")
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.body<String>().contains("[]"))
    }
}
