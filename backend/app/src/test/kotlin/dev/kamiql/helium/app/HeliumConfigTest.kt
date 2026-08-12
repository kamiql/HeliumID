package dev.kamiql.helium.app

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Configuration is read exactly once, from names that exist nowhere else in the type system.
 *
 * A typo in one of those names does not fail to compile and does not fail at startup — it
 * silently disables whatever the variable controlled. That already happened once here: a
 * botched string interpolation turned `HELIUM_GOOGLE_CLIENT_ID` into `HELIUM__CLIENT_ID`, and
 * the only symptom was an empty provider list on the login page.
 *
 * So these tests assert the literal variable names. They look tautological; that is the point.
 */
class HeliumConfigTest {

    /** The minimum a config needs to be constructible at all. */
    private fun baseEnv(vararg extra: Pair<String, String>): Map<String, String> = buildMap {
        put("HELIUM_ENV", "dev")
        put("HELIUM_DATA_KEYS", "1:${base64(32)}")
        put("HELIUM_TOKEN_HMAC_KEY", base64(32))
        put("HELIUM_DB_URL", "jdbc:postgresql://localhost:5432/helium")
        putAll(extra)
    }

    private fun base64(bytes: Int) = Base64.getEncoder().encodeToString(ByteArray(bytes) { 7 })

    private fun config(env: Map<String, String>) = HeliumConfig.fromEnvironment { env[it] }

    @Test
    fun `provider credentials are read from the documented variable names`() {
        val config = config(
            baseEnv(
                "HELIUM_GOOGLE_CLIENT_ID" to "google-id",
                "HELIUM_GOOGLE_CLIENT_SECRET" to "google-secret",
                "HELIUM_GITHUB_CLIENT_ID" to "github-id",
                "HELIUM_GITHUB_CLIENT_SECRET" to "github-secret",
                "HELIUM_DISCORD_CLIENT_ID" to "discord-id",
                "HELIUM_DISCORD_CLIENT_SECRET" to "discord-secret",
            ),
        )

        assertEquals("google-id", assertNotNull(config.google).clientId)
        assertEquals("google-secret", assertNotNull(config.google).clientSecret.reveal())
        assertEquals("github-id", assertNotNull(config.github).clientId)
        assertEquals("github-secret", assertNotNull(config.github).clientSecret.reveal())
        assertEquals("discord-id", assertNotNull(config.discord).clientId)
        assertEquals("discord-secret", assertNotNull(config.discord).clientSecret.reveal())
    }

    @Test
    fun `a provider is disabled unless both halves are present`() {
        // Half-configured must mean off, not "on and broken at redirect time".
        val idOnly = config(baseEnv("HELIUM_GITHUB_CLIENT_ID" to "github-id"))
        assertNull(idOnly.github)

        val secretOnly = config(baseEnv("HELIUM_GITHUB_CLIENT_SECRET" to "github-secret"))
        assertNull(secretOnly.github)

        val none = config(baseEnv())
        assertNull(none.google)
        assertNull(none.github)
        assertNull(none.discord)
    }

    @Test
    fun `blank values count as absent`() {
        // An empty assignment in a .env file is how a credential gets "removed"; it must not
        // produce a provider configured with an empty client id.
        val config = config(
            baseEnv(
                "HELIUM_DISCORD_CLIENT_ID" to "   ",
                "HELIUM_DISCORD_CLIENT_SECRET" to "discord-secret",
            ),
        )
        assertNull(config.discord)
    }

    @Test
    fun `deployment variable aliases are honoured`() {
        // The compose manifests and the application were written against slightly different
        // vocabularies; both spellings must keep working or a redeploy silently loses a setting.
        val config = config(
            baseEnv(
                "HELIUM_HTTP_PORT" to "9090",
                "HELIUM_SAME_SITE" to "Strict",
                "HELIUM_DB_MAX_POOL_SIZE" to "42",
            ),
        )

        assertEquals(9090, config.port)
        assertEquals("Strict", config.sameSite)
        assertEquals(42, config.database.maxPoolSize)
    }

    @Test
    fun `production refuses a development-shaped configuration`() {
        val problems = assertFailsWith<IllegalArgumentException> {
            config(
                baseEnv(
                    "HELIUM_ENV" to "prod",
                    "HELIUM_ISSUER_URL" to "http://id.example.com",
                    "HELIUM_SECURE_COOKIES" to "false",
                ),
            ).validate()
        }.message.orEmpty()

        assertTrue(problems.contains("https"), "plaintext issuer must be rejected")
        assertTrue(problems.contains("HELIUM_SECURE_COOKIES"), "insecure cookies must be rejected")
    }

    @Test
    fun `the bootstrap administrator cannot exist in production`() {
        // Three guards protect this; the first is that the variables are simply not read.
        val config = config(
            baseEnv(
                "HELIUM_ENV" to "prod",
                "HELIUM_BOOTSTRAP_ADMIN_USERNAME" to "admin",
                "HELIUM_BOOTSTRAP_ADMIN_EMAIL" to "admin@example.com",
                "HELIUM_BOOTSTRAP_ADMIN_PASSWORD" to "hunter2",
            ),
        )
        assertNull(config.bootstrapAdmin)
    }

    @Test
    fun `an unknown environment value defaults to production`() {
        // Failing safe: a typo in HELIUM_ENV must not quietly unlock development behaviour.
        assertEquals(HeliumEnvironment.PROD, HeliumEnvironment.parse("developement"))
        assertEquals(HeliumEnvironment.PROD, HeliumEnvironment.parse(null))
        assertEquals(HeliumEnvironment.DEV, HeliumEnvironment.parse("dev"))
        assertEquals(HeliumEnvironment.DEV, HeliumEnvironment.parse("DEV"))
    }
}
