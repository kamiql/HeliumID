package dev.kamiql.helium.app

import dev.kamiql.helium.app.support.heliumTest
import io.ktor.client.call.body
import io.ktor.http.HttpStatusCode
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The administrative read surface, and the boundary around it.
 *
 * Every one of these routes hands over data about *other people*, so the assertion that matters
 * on each is the same: an ordinary account gets nothing. The listings themselves are thin — the
 * interesting behaviour of the write routes lives in their flows and is tested there — but the
 * permission check is HTTP-level composition, and only an assembled server can demonstrate it.
 */
@Tag("integration")
class AdminSurfaceTest {

    @Test
    fun `an administrator can read users, roles, permissions, scopes and clients`() = heliumTest {
        val admin = actors.admin()

        assertEquals(HttpStatusCode.OK, http.get("/v1/admin/users").status)
        assertEquals(HttpStatusCode.OK, http.get("/v1/admin/roles").status)
        assertEquals(HttpStatusCode.OK, http.get("/v1/admin/permissions").status)
        assertEquals(HttpStatusCode.OK, http.get("/v1/admin/scopes").status)
        assertEquals(HttpStatusCode.OK, http.get("/v1/admin/clients").status)

        val user = http.get("/v1/admin/users/{userId}", "userId" to admin.userId.value.toString())
        assertEquals(HttpStatusCode.OK, user.status)
        assertTrue(user.body<String>().contains(admin.username))
    }

    /**
     * The whole point of the section.
     *
     * A signed-in user with no `admin:*` permission must be refused everywhere here — and refused
     * with `403`, not `404`: they are authenticated and the route exists, so pretending otherwise
     * would only muddy the audit trail without hiding anything they could not already infer.
     */
    @Test
    fun `an ordinary account is refused everywhere under admin`() = heliumTest {
        val account = actors.user()

        listOf(
            "/v1/admin/users",
            "/v1/admin/roles",
            "/v1/admin/permissions",
            "/v1/admin/scopes",
            "/v1/admin/clients",
        ).forEach { route ->
            assertEquals(HttpStatusCode.Forbidden, http.get(route).status, "$route was not protected")
        }

        assertEquals(
            HttpStatusCode.Forbidden,
            http.get("/v1/admin/users/{userId}", "userId" to account.userId.value.toString()).status,
            "reading your own record through the admin API is still an admin action",
        )
    }

    @Test
    fun `an anonymous caller is refused before authorization is even considered`() = heliumTest {
        assertEquals(HttpStatusCode.Unauthorized, http.get("/v1/admin/users").status)
    }

    @Test
    fun `a registered client can be read back`() = heliumTest {
        actors.admin()

        // Registration itself is covered by AuthorizedAppsE2eTest; this is the read-back path.
        val listed = http.get("/v1/admin/clients")
        assertEquals(HttpStatusCode.OK, listed.status)

        val response = http.get("/v1/admin/clients/{clientId}", "clientId" to "definitely-not-registered")
        assertEquals(HttpStatusCode.NotFound, response.status)
    }
}
