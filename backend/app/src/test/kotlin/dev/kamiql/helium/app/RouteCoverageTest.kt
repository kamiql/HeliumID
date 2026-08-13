package dev.kamiql.helium.app

import dev.kamiql.helium.api.testing.RouteInventory
import dev.kamiql.helium.api.testing.RouteKey
import dev.kamiql.helium.app.support.RouteCensus
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Fails when a registered route is not reached by any end-to-end test.
 *
 * `RouteInventoryTest` in `api-http` already guarantees that `docs/api-routes.md` lists exactly
 * what the routing tree registers. This closes the other half: that the list is *exercised*. The
 * two together mean a new endpoint cannot be added quietly — it fails the inventory until it is
 * documented, and fails here until it is tested.
 *
 * ### The baseline, and why there is one
 *
 * [NOT_YET_EXERCISED] is a ratchet, not an exemption list. Coverage was introduced against an API
 * that already existed, and a check that goes red on arrival gets switched off. So the routes
 * that had no end-to-end test on the day this landed are written down, and the test fails in
 * *both* directions:
 *
 *  * a route outside the baseline that nobody exercised — the new-endpoint case;
 *  * a route *in* the baseline that is now exercised — so the list can only shrink, and cannot
 *    quietly outlive the gap it describes.
 *
 * Deleting the last entry deletes the mechanism. That is the intended end state.
 *
 * ### Reading a failure here after a filtered run
 *
 * The census counts what this JVM executed. `--tests` filtering therefore fails it by
 * construction; that is not a defect, it is the census correctly reporting that most routes went
 * untouched. Run `:app:integrationTest` without a filter before believing it.
 */
@Tag("integration")
@Order(Int.MAX_VALUE)
class RouteCoverageTest {

    /**
     * Routes with no end-to-end coverage yet, each with the reason it is hard rather than merely
     * untouched. Shrink this list; never extend it without the same kind of note.
     */
    private val notYetExercised: Set<RouteKey> = NOT_YET_EXERCISED.keys

    @Test
    fun `every registered route is exercised by an end-to-end test`() {
        val documented = RouteInventory.fromMarkdown(Files.readString(routeDocument()))
        assertTrue(
            documented.isNotEmpty(),
            "docs/api-routes.md lists no routes; regenerate it before trusting this census",
        )

        val exercised = RouteCensus.exercised()

        val unknown = exercised - documented.toSet()
        assertEquals(
            emptySet(), unknown,
            """
            A test exercised a route that is not in docs/api-routes.md.

            That means the template it asked for does not match any registered route — the
            request 404'd and the assertion on it was meaningless. Fix the template, or
            regenerate the document if the route is genuinely new.
            """.trimIndent(),
        )

        val expected = documented.toSet() - notYetExercised
        val missing = (expected - exercised).sorted()
        assertEquals(
            emptyList(), missing,
            """
            These routes are registered but no end-to-end test reaches them.

            Add one, or — if it genuinely cannot be driven through HTTP yet — add it to
            RouteCoverageTest.NOT_YET_EXERCISED with the reason.

            (Running a filtered subset with --tests will always fail this. Run the whole
            :app:integrationTest suite.)
            """.trimIndent(),
        )

        val newlyCovered = (notYetExercised intersect exercised).sorted()
        assertEquals(
            emptyList(), newlyCovered,
            """
            These routes are listed in RouteCoverageTest.NOT_YET_EXERCISED but are now covered.

            Remove them from the baseline. The list is a ratchet: leaving a covered route in it
            means the next regression on that route goes unnoticed.
            """.trimIndent(),
        )
    }

    private fun routeDocument(): Path {
        var candidate: Path? = Path.of("").toAbsolutePath()
        while (candidate != null) {
            val document = candidate.resolve("docs/api-routes.md")
            if (Files.exists(document)) return document
            candidate = candidate.parent
        }
        fail("could not find docs/api-routes.md from ${Path.of("").toAbsolutePath()}")
    }

    private companion object {

        /**
         * The gap, with a reason per entry.
         *
         * Grouped by why, because the reasons are not equivalent: some of these need an external
         * system to exist, and some are simply not written yet.
         */
        val NOT_YET_EXERCISED: Map<RouteKey, String> = buildMap {
            // --- needs a browser-grade authenticator ------------------------------------
            // WebAuthn registration and assertion are signed by a security key. Driving them
            // means a software authenticator built on webauthn4j's test tooling; `mfa-webauthn`
            // has that, and it belongs there rather than reimplemented over HTTP.
            put("POST /v1/me/mfa/webauthn/enroll", "needs a software authenticator")
            put("POST /v1/me/mfa/webauthn/confirm", "needs a software authenticator")
            put("POST /v1/me/mfa/webauthn/remove", "needs a software authenticator")

            // --- needs a configured external provider -----------------------------------
            // The test configuration declares no Google, GitHub or Discord credentials, and the
            // registry is built from configuration precisely so that providers cannot be
            // invented at runtime. Covering these means a stub provider in the SPI, which is a
            // change to production wiring and so its own piece of work.
            put("GET /v1/auth/providers/{provider}/start", "no provider configured in the test graph")
            put("GET /v1/auth/providers/{provider}/callback", "no provider configured in the test graph")
            put("DELETE /v1/me/providers/{provider}", "no provider configured in the test graph")

            // --- not yet written ---------------------------------------------------------
            put("POST /v1/me/delete", "not yet written")
            put("POST /v1/me/email-change", "not yet written")
            put("POST /v1/me/email-change/confirm", "not yet written")
            put("POST /v1/me/mfa/totp/enroll", "not yet written")
            put("POST /v1/me/mfa/totp/confirm", "not yet written")
            put("POST /v1/me/mfa/totp/disable", "not yet written")
            put("POST /v1/me/mfa/recovery-codes", "not yet written")
            put("POST /v1/auth/mfa/challenge", "not yet written")
            put("POST /v1/auth/mfa/verify", "not yet written")
            // Same gap as `/v1/auth/mfa/verify`: reaching it means an account with a live second
            // factor, and nothing in this suite enrols one over HTTP yet. The step-up path
            // *without* a factor is covered — see AccountLifecycleTest.
            put("POST /v1/auth/reauthenticate/mfa", "needs an enrolled second factor; see /v1/auth/mfa/verify")
            put("GET /v1/me/trusted-devices", "not yet written")
            put("DELETE /v1/me/trusted-devices", "not yet written")
            put("DELETE /v1/me/trusted-devices/{id}", "not yet written")
            put("POST /oauth2/introspect", "not yet written")
            put("POST /oauth2/revoke", "not yet written")
            put("GET /v1/admin/audit", "not yet written")
            put("PATCH /v1/admin/clients/{clientId}", "not yet written")
            put("DELETE /v1/admin/clients/{clientId}", "not yet written")
            put("POST /v1/admin/clients/{clientId}/rotate-secret", "not yet written")
            put("PUT /v1/admin/roles/{name}", "not yet written")
            put("DELETE /v1/admin/roles/{name}", "not yet written")
            put("PUT /v1/admin/scopes/{name}", "not yet written")
            put("DELETE /v1/admin/scopes/{name}", "not yet written")
            put("PUT /v1/admin/users/{userId}/status", "not yet written")
            put("PUT /v1/admin/users/{userId}/roles", "not yet written")
            put("GET /v1/admin/users/{userId}/sessions", "not yet written")
            put("POST /v1/admin/users/{userId}/revoke-sessions", "not yet written")
        }.mapKeys { (line, _) -> RouteKey.parse(line) }
    }
}
