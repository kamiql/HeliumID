package dev.kamiql.helium.demo

import dev.kamiql.helium.client.HeliumApiException
import dev.kamiql.helium.client.HeliumError
import dev.kamiql.helium.client.HeliumIdClient
import dev.kamiql.helium.client.RegisterClientRequest
import dev.kamiql.helium.client.UpsertScopeRequest
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.cookies.HttpCookies
import kotlinx.coroutines.runBlocking

/**
 * One-off setup: registers the scopes and the OAuth client this demo runs against.
 *
 *     ./gradlew setup
 *
 * ### Why this needs a password rather than a token
 *
 * Client registration goes through a flow that declares `ReauthenticatedWithin(5 minutes)`, and
 * that requirement rejects **any** principal that is not a browser session — a `client_credentials`
 * token can never satisfy it, no matter which permissions the client holds. So the only way to
 * automate registration is to do what a browser does: sign in, then act inside the reauthentication
 * window. That is a deliberate constraint in HeliumID, not an oversight, and any integrator
 * scripting client registration will meet it.
 *
 * Hence the shape below: a cookie-aware HTTP client, a session bootstrap for the CSRF token, a
 * login, and a second bootstrap because the server rotates the CSRF token on authentication.
 */
fun main(): Unit = runBlocking {
    val config = DemoConfig.fromEnvironment()
    val credentials = SetupCredentials.fromEnvironment()

    // A cookie-aware engine. The SDK's bundled client is stateless, which is right for bearer
    // traffic and useless for a session.
    val http = HttpClient(CIO) { install(HttpCookies) }

    // Read once per request. The server issues a fresh CSRF token on sign-in, so a value captured
    // before login is worthless afterwards — holding it in a var and re-reading it is the point.
    var csrf: String? = null
    val client = HeliumIdClient.create(config.issuer) {
        httpClient = http
        csrfToken { csrf }
    }

    client.use {
        println("HeliumID: ${config.issuer}")

        csrf = client.session().csrfToken

        try {
            client.login(credentials.username, credentials.password)
        } catch (failure: HeliumApiException) {
            when (failure.error) {
                is HeliumError.MfaRequired -> abort(
                    """
                    The administrator account has MFA enabled, and this script cannot complete a
                    challenge. Register the client by hand in the console at ${config.issuer}
                    (Admin -> Clients), or use an account without a second factor.
                    """.trimIndent(),
                )
                is HeliumError.InvalidCredentials -> abort(
                    """
                    Sign-in was refused for '${credentials.username}'. Set HELIUM_ADMIN_USERNAME and
                    HELIUM_ADMIN_PASSWORD to the bootstrap administrator from your .env.dev.
                    """.trimIndent(),
                )
                else -> throw failure
            }
        }

        // Re-read: authentication rotated the token, and every write below is state-changing.
        csrf = client.session().csrfToken
        println("signed in as ${credentials.username}")

        registerScopes(client)
        registerClient(client, config)
    }
}

/**
 * The two scopes this application's own API is authorized with.
 *
 * They have to exist before the client can be registered against them: registration rejects any
 * scope the catalogue does not know, and `oauth_client_scopes.scope` has a foreign key onto it.
 */
private suspend fun registerScopes(client: HeliumIdClient) {
    val scopes = mapOf(
        DemoConfig.SCOPE_WORKSPACE_READ to "See the documents shared with you",
        DemoConfig.SCOPE_WORKSPACE_WRITE to "Create and edit documents on your behalf",
    )

    scopes.forEach { (name, description) ->
        // Written as a sentence, in the second person: this string is rendered verbatim on the
        // consent screen, where "workspace:write" would tell a user nothing.
        val scope = client.upsertScope(name, UpsertScopeRequest(description = description))
        println("scope ${scope.name}: ${scope.description}")
    }
}

private suspend fun registerClient(client: HeliumIdClient, config: DemoConfig) {
    val request = RegisterClientRequest(
        clientId = config.clientId,
        name = "Helium Demo Workspace",
        // Confidential: this is a server-side application that can hold a secret, so the token
        // exchange is authenticated with one *in addition* to PKCE.
        type = "CONFIDENTIAL",
        // Exact-match allowlist. No normalization, no trailing-slash tolerance.
        redirectUris = listOf(config.redirectUri),
        scopes = config.scopes.toList(),
        grantTypes = listOf("authorization_code", "refresh_token"),
        // Becomes the `aud` claim of every access token issued to this client, and what the
        // demo's own bearer API validates against.
        audiences = listOf(config.audience),
        // Left off deliberately: showing the real consent screen is part of the demo.
        skipConsent = false,
    )

    val issued = try {
        client.registerClient(request)
    } catch (failure: HeliumApiException) {
        if (failure.error is HeliumError.Conflict) {
            abort(
                """
                A client named '${config.clientId}' already exists.
                Its secret cannot be read back — rotate it in the console (Admin -> Clients ->
                Rotate secret) or delete the client and run this again.
                """.trimIndent(),
            )
        }
        throw failure
    }

    println(
        """

        Client registered.

          DEMO_CLIENT_ID=${issued.clientId}
          DEMO_CLIENT_SECRET=${issued.secret}

        This is the only time the secret is shown. Export both and start the app:

          ${'$'}env:DEMO_CLIENT_SECRET="${issued.secret}"   # PowerShell
          export DEMO_CLIENT_SECRET="${issued.secret}"       # bash
          ./gradlew run
        """.trimIndent(),
    )
}

private fun abort(message: String): Nothing {
    System.err.println("\n$message\n")
    kotlin.system.exitProcess(1)
}
