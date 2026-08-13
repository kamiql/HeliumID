package dev.kamiql.helium.app

import dev.kamiql.helium.api.ChangePasswordRequest
import dev.kamiql.helium.api.EmailRequest
import dev.kamiql.helium.api.LoginRequest
import dev.kamiql.helium.api.PasswordResetCompleteRequest
import dev.kamiql.helium.api.ReauthenticateRequest
import dev.kamiql.helium.api.RegisterRequest
import dev.kamiql.helium.api.SessionBootstrapResponse
import dev.kamiql.helium.api.SessionResponse
import dev.kamiql.helium.api.TokenRequestBody
import dev.kamiql.helium.api.UserResponse
import dev.kamiql.helium.app.support.bootstrapCsrf
import dev.kamiql.helium.app.support.heliumTest
import dev.kamiql.helium.domain.common.SessionId
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Registration through to sign-out, against the assembled server.
 *
 * These are the paths that only exist once everything is wired: a verification token that a flow
 * writes to the outbox and a route reads back, a session cookie the composition root configures
 * and the principal resolver has to accept, a CSRF pair that rotates on authentication. Every one
 * of them is invisible to a module test holding fakes on both sides.
 */
@Tag("integration")
class AccountLifecycleTest {

    @Test
    fun `bootstrap answers anonymously and still issues a CSRF token`() = heliumTest {
        val response = http.get("/v1/auth/session")

        assertEquals(HttpStatusCode.OK, response.status, "bootstrap must never 401")
        val body = response.body<SessionBootstrapResponse>()
        assertFalse(body.authenticated)
        assertNull(body.user)
        assertTrue(body.csrfToken.isNotBlank(), "an anonymous caller still needs a token to sign in with")
    }

    @Test
    fun `register, verify, sign in, read the profile, sign out`() = heliumTest {
        http.bootstrapCsrf()

        val registered = http.post("/v1/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest("lifecycle", "lifecycle@helium.test", PASSWORD))
        }
        assertEquals(HttpStatusCode.Accepted, registered.status)

        val token = outbox.emailVerificationToken()
        val verified = http.post("/v1/auth/email/verify") {
            contentType(ContentType.Application.Json)
            setBody(TokenRequestBody(token))
        }
        assertEquals(HttpStatusCode.NoContent, verified.status)

        val signedIn = http.post("/v1/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest("lifecycle", PASSWORD))
        }
        assertEquals(HttpStatusCode.NoContent, signedIn.status)

        val profile = http.get("/v1/me").body<UserResponse>()
        assertEquals("lifecycle", profile.username)
        assertTrue(profile.emailVerified)

        assertEquals(HttpStatusCode.NoContent, http.post("/v1/auth/logout").status)

        assertEquals(
            HttpStatusCode.Unauthorized, http.get("/v1/me").status,
            "the session cookie must stop working the moment it is revoked",
        )
    }

    /**
     * The same token twice.
     *
     * A verification link lands in an inbox and is followed by a mail client's link-preview as
     * often as by a person, so a second redemption is a routine event, not an attack — and it
     * must fail closed rather than re-verify an address that may have changed since.
     */
    @Test
    fun `a verification token cannot be redeemed twice`() = heliumTest {
        http.bootstrapCsrf()
        http.post("/v1/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest("replay", "replay@helium.test", PASSWORD))
        }

        val token = outbox.emailVerificationToken()
        val body: (io.ktor.client.request.HttpRequestBuilder).() -> Unit = {
            contentType(ContentType.Application.Json)
            setBody(TokenRequestBody(token))
        }

        assertEquals(HttpStatusCode.NoContent, http.post("/v1/auth/email/verify", block = body).status)
        assertEquals(
            HttpStatusCode.Unauthorized,
            http.post("/v1/auth/email/verify", block = body).status,
            "a consumed token must not be redeemable again",
        )
    }

    /**
     * An unverified account may sign in, and is then held short of anything that matters.
     *
     * Worth pinning down, because it looks like a gap and is not. Registration leaves the user
     * `PENDING_EMAIL_VERIFICATION` and login accepts that status deliberately: refusing the
     * session would leave somebody who mistyped their address with no authenticated surface to
     * fix it from, and would make "is this address registered" observable at the login endpoint.
     * The gate lives one level in, on the flows that declare `EmailVerified` — so what has to be
     * true is not *no session*, but *no consequential action*.
     */
    @Test
    fun `an unverified account signs in but cannot change its password`() = heliumTest {
        http.bootstrapCsrf()
        http.post("/v1/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest("unverified", "unverified@helium.test", PASSWORD))
        }

        val signedIn = http.post("/v1/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest("unverified", PASSWORD))
        }
        assertEquals(HttpStatusCode.NoContent, signedIn.status)

        val profile = http.get("/v1/me").body<UserResponse>()
        assertFalse(profile.emailVerified)

        val changed = http.put("/v1/me/password") {
            contentType(ContentType.Application.Json)
            setBody(ChangePasswordRequest(PASSWORD, NEW_PASSWORD))
        }
        assertEquals(
            HttpStatusCode.Forbidden, changed.status,
            "an unverified account must not be able to change its password",
        )
    }

    /**
     * A step-up refreshes the session it ran for, and starts no other.
     *
     * The regression pinned here was user-visible. The account UI satisfied a step-up prompt by
     * replaying `POST /v1/auth/login`, which mints a session — so confirming a deletion, then a
     * password change, then an MFA edit left three extra entries in the device list, all from one
     * browser and none of them recognisable. A list that grows by one per sensitive action is a
     * list nobody reads, which is the opposite of what it is for.
     *
     * The clock is backdated rather than waited out: the window is five minutes, and a test that
     * sleeps through it is a test nobody runs. Doing it through `markAuthenticated` also means a
     * no-op implementation cannot pass — the `403` below would not appear.
     */
    @Test
    fun `re-authenticating refreshes the current session rather than starting another`() = heliumTest {
        val account = actors.user()

        val before = http.get("/v1/me/sessions").body<List<SessionResponse>>().single()
        val sessionId = assertNotNull(SessionId.parse(before.id))

        components.sessions.markAuthenticated(
            id = sessionId,
            at = Instant.now().minus(Duration.ofHours(1)),
            methods = emptySet(),
        )

        val stale = http.put("/v1/me/password") {
            contentType(ContentType.Application.Json)
            setBody(ChangePasswordRequest(account.password, NEW_PASSWORD))
        }
        assertEquals(
            HttpStatusCode.Unauthorized, stale.status,
            "a session that last proved itself an hour ago must not change a password",
        )

        val stepped = http.post("/v1/auth/reauthenticate") {
            contentType(ContentType.Application.Json)
            setBody(ReauthenticateRequest(account.password))
        }
        assertEquals(HttpStatusCode.NoContent, stepped.status)

        val after = http.get("/v1/me/sessions").body<List<SessionResponse>>()
        assertEquals(1, after.size, "the step-up must not have started a second session")
        assertEquals(before.id, after.single().id, "and it must be the session the browser already had")

        val changed = http.put("/v1/me/password") {
            contentType(ContentType.Application.Json)
            setBody(ChangePasswordRequest(account.password, NEW_PASSWORD))
        }
        assertEquals(
            HttpStatusCode.NoContent, changed.status,
            "the step-up must have satisfied the freshness requirement it was prompted by",
        )
    }

    /** A wrong password buys nothing — not a session, and not a refreshed clock. */
    @Test
    fun `a step-up with the wrong password is refused and changes nothing`() = heliumTest {
        actors.user()

        val response = http.post("/v1/auth/reauthenticate") {
            contentType(ContentType.Application.Json)
            setBody(ReauthenticateRequest("not-the-password"))
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(
            1, http.get("/v1/me/sessions").body<List<SessionResponse>>().size,
            "a failed step-up must not leave a session behind either",
        )
    }

    /**
     * Anonymous callers are told to sign in, not asked for a password.
     *
     * The distinction matters: this endpoint refreshes *a* session, so a caller without one has
     * nothing for it to act on. Accepting a password here would quietly make it a second login
     * route — one that issues no cookie and so would appear to succeed and do nothing.
     */
    @Test
    fun `a step-up without a session is refused`() = heliumTest {
        http.bootstrapCsrf()

        val response = http.post("/v1/auth/reauthenticate") {
            contentType(ContentType.Application.Json)
            setBody(ReauthenticateRequest(PASSWORD))
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    /**
     * Registration and resend answer the same way for an address that exists and one that does
     * not (concept §2.6).
     */
    @Test
    fun `neither registration nor resend reveals whether an address is taken`() = heliumTest {
        http.bootstrapCsrf()

        val first = http.post("/v1/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest("taken", "taken@helium.test", PASSWORD))
        }
        val second = http.post("/v1/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest("taken2", "taken@helium.test", PASSWORD))
        }

        assertEquals(first.status, second.status, "a duplicate address must be indistinguishable")
        assertEquals(first.bodyText(), second.bodyText())

        val known = http.post("/v1/auth/email/resend") {
            contentType(ContentType.Application.Json)
            setBody(EmailRequest("taken@helium.test"))
        }
        val unknown = http.post("/v1/auth/email/resend") {
            contentType(ContentType.Application.Json)
            setBody(EmailRequest("nobody@helium.test"))
        }
        assertEquals(known.status, unknown.status)
        assertEquals(known.bodyText(), unknown.bodyText())
    }

    @Test
    fun `password reset issues a token, changes the password and invalidates the old one`() = heliumTest {
        val account = actors.create()

        val requested = http.post("/v1/auth/password-reset/request") {
            contentType(ContentType.Application.Json)
            setBody(EmailRequest(account.email))
        }
        assertEquals(HttpStatusCode.Accepted, requested.status)

        val token = outbox.passwordResetToken()
        val completed = http.post("/v1/auth/password-reset/complete") {
            contentType(ContentType.Application.Json)
            setBody(PasswordResetCompleteRequest(token, NEW_PASSWORD))
        }
        assertEquals(HttpStatusCode.NoContent, completed.status)

        val withOld = http.post("/v1/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(account.username, account.password))
        }
        assertEquals(HttpStatusCode.Unauthorized, withOld.status, "the old password must stop working")

        val withNew = http.post("/v1/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(account.username, NEW_PASSWORD))
        }
        assertEquals(HttpStatusCode.NoContent, withNew.status)
    }

    /** An unknown address must produce the same answer, and no token. */
    @Test
    fun `password reset for an unknown address is indistinguishable and issues nothing`() = heliumTest {
        http.bootstrapCsrf()

        val response = http.post("/v1/auth/password-reset/request") {
            contentType(ContentType.Application.Json)
            setBody(EmailRequest("ghost@helium.test"))
        }

        assertEquals(HttpStatusCode.Accepted, response.status)
        outbox.assertNone("user.password-reset-requested")
    }

    /**
     * The CSRF pair is enforced, and the harness is not quietly satisfying it.
     *
     * Uses [rawHttp] deliberately: the wrapped client attaches the header, so proving the check
     * exists means going around it. Without this test the whole suite could be passing against a
     * server that had no CSRF defence at all.
     */
    @Test
    fun `a state change without the CSRF header is refused`() = heliumTest {
        http.bootstrapCsrf() // the cookie is present; only the header is missing

        val response = rawHttp.post("/v1/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest("csrfless", "csrfless@helium.test", PASSWORD))
        }

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(
            components.users.findByLoginIdentifier("csrfless"),
            "a rejected request must not have created anything",
        )
    }

    @Test
    fun `the password policy is published for the sign-up form`() = heliumTest {
        val response = http.get("/v1/auth/password-requirements")
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.bodyText().contains("min_length"), "the SPA reads snake_case fields")
    }

    private companion object {
        const val PASSWORD = "correct-horse-battery-staple-42"
        const val NEW_PASSWORD = "a-different-long-passphrase-99"
    }
}

private suspend fun io.ktor.client.statement.HttpResponse.bodyText(): String = body()
