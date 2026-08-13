package dev.kamiql.helium.demo

/**
 * Everything the demo needs to talk to HeliumID.
 *
 * Read from the environment rather than a file so nothing here can be committed by accident —
 * [clientSecret] in particular is a real credential, and the whole reason this application is a
 * *confidential* client is that it can keep one.
 *
 * The defaults describe the dev stack from `docker-compose.dev.yml`. Only the secret has no
 * default: it is minted once by `./gradlew setup` and cannot be recovered afterwards.
 */
data class DemoConfig(
    /** HeliumID's origin. Must match the `iss` claim exactly — validation is exact-match. */
    val issuer: String,
    /** Where this app is reachable. The redirect URI is derived from it and must be registered. */
    val baseUrl: String,
    val port: Int,
    val clientId: String,
    val clientSecret: String,
    /**
     * The `aud` value HeliumID puts in access tokens for this client, and the value this app's
     * own bearer API validates. Registered as the client's `audiences`.
     */
    val audience: String,
    /** Scopes requested at login. `openid` is what makes an ID token appear at all. */
    val scopes: Set<String>,
) {
    val redirectUri: String get() = "$baseUrl/callback"

    companion object {
        const val SCOPE_WORKSPACE_READ = "workspace:read"
        const val SCOPE_WORKSPACE_WRITE = "workspace:write"

        fun fromEnvironment(): DemoConfig {
            val baseUrl = env("DEMO_BASE_URL", "http://localhost:8081").trimEnd('/')
            return DemoConfig(
                issuer = env("HELIUM_ISSUER", "http://localhost:90").trimEnd('/'),
                baseUrl = baseUrl,
                port = env("DEMO_PORT", "8081").toInt(),
                clientId = env("DEMO_CLIENT_ID", "helium-demo"),
                clientSecret = System.getenv("DEMO_CLIENT_SECRET").orEmpty(),
                audience = env("DEMO_AUDIENCE", "helium-demo-api"),
                scopes = setOf(
                    "openid",
                    "profile",
                    "email",
                    // Not what actually grants a refresh token — that depends on the client's
                    // registered grant types — but requesting it is the conventional signal and
                    // it shows up on the consent screen.
                    "offline_access",
                    SCOPE_WORKSPACE_READ,
                    SCOPE_WORKSPACE_WRITE,
                ),
            )
        }

        private fun env(name: String, default: String): String =
            System.getenv(name)?.takeIf { it.isNotBlank() } ?: default
    }
}

/** Credentials the setup CLI signs in with. Never used by the running application. */
data class SetupCredentials(val username: String, val password: String) {
    companion object {
        fun fromEnvironment(): SetupCredentials = SetupCredentials(
            username = System.getenv("HELIUM_ADMIN_USERNAME") ?: "admin",
            // Matches HELIUM_BOOTSTRAP_ADMIN_PASSWORD in .env.dev.example.
            password = System.getenv("HELIUM_ADMIN_PASSWORD") ?: "dev-only-change-me",
        )
    }

    override fun toString(): String = "SetupCredentials(username=$username, password=***)"
}
