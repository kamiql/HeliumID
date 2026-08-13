package dev.kamiql.helium.api

import dev.kamiql.helium.api.testing.RouteInventory
import dev.kamiql.helium.api.testing.RouteKey
import io.ktor.server.testing.testApplication
import io.mockk.mockk
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Holds `docs/api-routes.md` to the routing tree.
 *
 * The document is generated, not written: it is the inventory the end-to-end coverage census in
 * `app` measures against, so it has to be a fact about the code rather than a description
 * somebody kept up to date. Adding a route without regenerating fails here; adding one without
 * testing it fails in `:app:integrationTest`.
 *
 * Registration runs against a stub dependency bundle. That is safe because every handler body is
 * a lambda — nothing in `heliumRoutes` touches a repository until a request arrives — and it is
 * what keeps this suite in `./gradlew build`: no container, no database, no network.
 */
class RouteInventoryTest {

    /** Set `-Dhelium.routes.write=true` to regenerate the document instead of asserting on it. */
    private val writeMode = System.getProperty("helium.routes.write") == "true"

    @Test
    fun `documented routes match the routing tree`() = testApplication {
        application {
            installHeliumApi(
                security = testSecurityConfig(),
                dependencies = mockk(relaxed = true),
                metrics = StubMetrics,
                readiness = { true },
            )
        }
        // `testApplication` builds the application lazily; nothing is registered until it starts.
        startApplication()

        val registered = RouteInventory.of(application)
        assertTrue(registered.isNotEmpty(), "enumerated no routes at all — the walk is broken")

        val document = repositoryRoot().resolve("docs/api-routes.md")

        if (writeMode) {
            Files.createDirectories(document.parent)
            Files.writeString(document, RouteInventory.toMarkdown(registered))
            return@testApplication
        }

        if (!Files.exists(document)) fail(regenerateHint("docs/api-routes.md does not exist"))

        val documented = RouteInventory.fromMarkdown(Files.readString(document))

        val undocumented = registered - documented.toSet()
        val phantom = documented - registered.toSet()

        assertEquals(
            emptyList(), undocumented,
            regenerateHint("these routes are registered but absent from docs/api-routes.md"),
        )
        assertEquals(
            emptyList(), phantom,
            regenerateHint("these routes are documented but no longer registered"),
        )
    }

    /**
     * Guards the enumerator itself.
     *
     * Without this, a walk that silently returned nothing — a renamed selector class, say — would
     * make the assertion above pass against an empty document and quietly certify nothing.
     */
    @Test
    fun `enumerator recovers methods and path parameters`() = testApplication {
        application {
            installHeliumApi(testSecurityConfig(), mockk(relaxed = true), StubMetrics) { true }
        }
        startApplication()

        val registered = RouteInventory.of(application).toSet()

        assertTrue(
            RouteKey.parse("GET /health") in registered,
            "health probe missing; plugins are not being installed",
        )
        assertTrue(
            RouteKey.parse("POST /v1/auth/login") in registered,
            "nested constant segments are not being joined",
        )
        assertTrue(
            RouteKey.parse("DELETE /v1/me/sessions/{sessionId}") in registered,
            "path parameters are not being rendered as templates",
        )
        assertTrue(
            RouteKey.parse("GET /.well-known/openid-configuration") in registered,
            "root-level protocol routes are being dropped",
        )
    }

    /** Enumeration only needs the route registered, never scraped. */
    private object StubMetrics : MetricsEndpoint {
        override fun scrape(): String = ""
    }

    private fun testSecurityConfig() = HttpSecurityConfig(
        issuerUrl = "https://helium.test",
        allowedOrigins = setOf("https://helium.test"),
        secureCookies = true,
    )

    private fun regenerateHint(problem: String): String =
        """
        $problem.

        Regenerate the document:
          cd backend && ./gradlew :api-http:test --tests '*RouteInventoryTest*' -Dhelium.routes.write=true

        Then confirm the new routes are covered by an end-to-end test, or :app:integrationTest
        will fail the coverage census.
        """.trimIndent()

    /**
     * Walks up from the module directory to the repository root.
     *
     * Gradle runs tests with the module as the working directory, and `docs/` sits two levels
     * above that. Searching for a marker rather than hard-coding `../..` keeps this working if
     * the module is ever moved.
     */
    private fun repositoryRoot(): Path {
        var candidate: Path? = Path.of("").toAbsolutePath()
        while (candidate != null) {
            if (Files.exists(candidate.resolve("CLAUDE.md")) && Files.isDirectory(candidate.resolve("docs"))) {
                return candidate
            }
            candidate = candidate.parent
        }
        fail("could not locate the repository root from ${Path.of("").toAbsolutePath()}")
    }
}
