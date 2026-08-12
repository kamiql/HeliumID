package dev.kamiql.helium.app

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.credential.PasswordHashParameters
import dev.kamiql.helium.domain.mfa.MfaPolicy
import dev.kamiql.helium.domain.policy.Lifetimes
import org.slf4j.LoggerFactory
import java.time.Duration

/**
 * Which environment this process believes it is running in.
 *
 * Not cosmetic: [DEV] relaxes cookie security, permits plaintext provider endpoints and enables
 * the bootstrap admin. Every one of those is a hole in production, so [HeliumConfig.validate]
 * refuses to start if a dev-shaped setting is present when this is [PROD].
 */
enum class HeliumEnvironment {
    DEV,
    STAGING,
    PROD,
    ;

    val isProduction: Boolean get() = this == PROD

    companion object {
        fun parse(raw: String?): HeliumEnvironment =
            entries.firstOrNull { it.name.equals(raw?.trim(), ignoreCase = true) } ?: PROD
    }
}

/**
 * What this process does. Lets the same image run as an API server, a worker, or both.
 *
 * [MIGRATE] is a one-shot: it applies pending migrations and exits, which is how production
 * runs them as a gated release step rather than as a side effect of a pod starting
 * (concept §3.4).
 */
enum class HeliumRole { API, WORKER, ALL, MIGRATE }

/**
 * The complete runtime configuration, resolved from the environment once at startup.
 *
 * Fail-fast is the design principle: a missing encryption key or a dev default in production
 * stops the process here rather than surfacing hours later as an undecryptable TOTP secret or
 * a session cookie that any site can read.
 */
data class HeliumConfig(
    val environment: HeliumEnvironment,
    val role: HeliumRole,
    val port: Int,
    val bindHost: String,
    val issuerUrl: String,
    val publicBaseUrl: String,
    val allowedOrigins: Set<String>,
    val secureCookies: Boolean,
    val sameSite: String,
    val trustForwardedHeaders: Boolean,

    val database: DatabaseSettings,
    val redisUrl: String?,

    val dataKeysBase64: String,
    val dataKeyVersion: Int,
    val tokenHmacKeyBase64: String,
    val passwordPepperBase64: String?,
    val passwordPepperVersion: Int,

    val argon2: PasswordHashParameters,
    val argon2Parallelism: Int,

    val lifetimes: Lifetimes,
    val mfaPolicy: MfaPolicy,

    val mail: MailSettings?,
    val google: ProviderCredentials?,
    val github: ProviderCredentials?,
    val discord: ProviderCredentials?,

    val bootstrapAdmin: BootstrapAdmin?,
) {

    data class DatabaseSettings(
        val jdbcUrl: String,
        val username: String,
        val password: String,
        val maxPoolSize: Int,
        val migrateOnStart: Boolean,
    )

    data class MailSettings(
        val host: String,
        val port: Int,
        val username: String?,
        val password: String?,
        val from: String,
        val fromName: String,
        val startTls: Boolean,
    )

    data class ProviderCredentials(val clientId: String, val clientSecret: Secret)

    /** Dev-only convenience so a fresh database is usable immediately. */
    data class BootstrapAdmin(val username: String, val email: String, val password: Secret)

    /**
     * Refuses to start on a configuration that is unsafe for [environment].
     *
     * Each check exists because the corresponding mistake is easy to make and silent at
     * runtime.
     */
    fun validate() {
        val problems = mutableListOf<String>()

        if (!issuerUrl.startsWith("https://") && environment.isProduction) {
            problems += "HELIUM_ISSUER_URL must be https in production"
        }
        if (environment.isProduction) {
            if (!secureCookies) {
                problems += "HELIUM_SECURE_COOKIES must be true in production"
            }
            if (bootstrapAdmin != null) {
                // A well-known admin credential in production is the single worst default a
                // system like this can ship with.
                problems += "HELIUM_BOOTSTRAP_ADMIN_* must not be set in production"
            }
            if (allowedOrigins.isEmpty()) {
                problems += "HELIUM_ALLOWED_ORIGINS must list the exact browser origins"
            }
            if (mail == null) {
                // Without mail there is no email verification and no password reset, and no
                // security notifications at all.
                problems += "HELIUM_SMTP_HOST must be configured in production"
            }
            if (database.migrateOnStart) {
                problems += "HELIUM_MIGRATE_ON_START should be false in production; run migrations as a release step"
            }
        }

        if (dataKeysBase64.isBlank()) problems += "HELIUM_DATA_KEYS is required"
        if (tokenHmacKeyBase64.isBlank()) problems += "HELIUM_TOKEN_HMAC_KEY is required"
        if (database.jdbcUrl.isBlank()) problems += "HELIUM_DB_URL is required"
        if (argon2.memoryKib < 19 * 1024) {
            // OWASP's floor for Argon2id. Below this the hash is cheap enough to brute force.
            problems += "HELIUM_ARGON2_MEMORY_KIB is below the 19456 KiB minimum"
        }
        if (redisUrl == null && environment.isProduction) {
            // In-memory rate limiting on several instances means the effective limit is
            // multiplied by the instance count.
            problems += "HELIUM_REDIS_URL is required in production for distributed rate limiting"
        }

        require(problems.isEmpty()) {
            "invalid configuration:\n" + problems.joinToString("\n") { "  - $it" }
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(HeliumConfig::class.java)

        /**
         * Reads the configuration from the process environment.
         *
         * @param source overridable for tests.
         */
        fun fromEnvironment(source: (String) -> String? = System::getenv): HeliumConfig {
            /**
             * Reads the first name that is set.
             *
             * Several settings have two accepted spellings because the deployment manifests
             * and the application were written against slightly different vocabularies.
             * Accepting both is cheaper than a rename that silently drops a setting in an
             * environment nobody re-deployed.
             */
            fun value(vararg names: String): String? =
                names.firstNotNullOfOrNull { source(it)?.trim()?.takeIf { v -> v.isNotEmpty() } }

            fun required(name: String): String =
                value(name) ?: error("required environment variable $name is not set")

            fun flag(name: String, default: Boolean, vararg aliases: String): Boolean =
                value(name, *aliases)?.lowercase()?.let { it == "true" || it == "1" || it == "yes" } ?: default

            fun number(name: String, default: Int, vararg aliases: String): Int =
                value(name, *aliases)?.toIntOrNull() ?: default

            val environment = HeliumEnvironment.parse(value("HELIUM_ENV"))
            val issuerUrl = value("HELIUM_ISSUER_URL") ?: "http://localhost:90"
            val secureCookies = flag("HELIUM_SECURE_COOKIES", environment.isProduction)

            val bootstrapAdmin = if (!environment.isProduction) {
                val username = value("HELIUM_BOOTSTRAP_ADMIN_USERNAME")
                val email = value("HELIUM_BOOTSTRAP_ADMIN_EMAIL")
                val password = value("HELIUM_BOOTSTRAP_ADMIN_PASSWORD")
                if (username != null && email != null && password != null) {
                    log.warn("bootstrap administrator is enabled; this must never happen in production")
                    BootstrapAdmin(username, email, Secret.of(password))
                } else {
                    null
                }
            } else {
                null
            }

            val mailHost = value("HELIUM_SMTP_HOST")
            val mail = mailHost?.let {
                MailSettings(
                    host = it,
                    port = number("HELIUM_SMTP_PORT", 587),
                    username = value("HELIUM_SMTP_USERNAME"),
                    password = value("HELIUM_SMTP_PASSWORD"),
                    from = value("HELIUM_MAIL_FROM") ?: "no-reply@localhost",
                    // Mailpit and other local sinks do not speak TLS.
                    startTls = flag("HELIUM_SMTP_STARTTLS", environment.isProduction, "HELIUM_SMTP_TLS"),
                    fromName = value("HELIUM_MAIL_FROM_NAME") ?: "HeliumID",
                )
            }

            /**
             * External provider credentials.
             *
             * A provider is enabled by the presence of *both* halves and disabled otherwise.
             * There is no explicit on/off flag on purpose: an enabled provider with a missing
             * secret would fail at the token exchange, halfway through a user-visible redirect,
             * which is a much worse place to discover a typo than startup.
             */
            fun providerCredentials(prefix: String): ProviderCredentials? =
                value("HELIUM_${prefix}_CLIENT_ID")?.let { clientId ->
                    value("HELIUM_${prefix}_CLIENT_SECRET")?.let { secret ->
                        ProviderCredentials(clientId, Secret.of(secret))
                    }
                }

            return HeliumConfig(
                environment = environment,
                role = HeliumRole.entries
                    .firstOrNull { it.name.equals(value("HELIUM_ROLE"), ignoreCase = true) } ?: HeliumRole.ALL,
                port = number("HELIUM_PORT", 8080, "HELIUM_HTTP_PORT"),
                bindHost = value("HELIUM_HTTP_HOST") ?: "0.0.0.0",
                issuerUrl = issuerUrl.trimEnd('/'),
                publicBaseUrl = (value("HELIUM_PUBLIC_BASE_URL") ?: issuerUrl).trimEnd('/'),
                allowedOrigins = value("HELIUM_ALLOWED_ORIGINS")
                    ?.split(',')?.map { it.trim().trimEnd('/') }?.filter { it.isNotEmpty() }?.toSet()
                    ?: setOf(issuerUrl.trimEnd('/')),
                secureCookies = secureCookies,
                sameSite = value("HELIUM_COOKIE_SAMESITE", "HELIUM_SAME_SITE") ?: "Lax",
                trustForwardedHeaders = flag("HELIUM_TRUST_FORWARDED_HEADERS", false),

                database = DatabaseSettings(
                    jdbcUrl = value("HELIUM_DB_URL")
                        ?: "jdbc:postgresql://postgres:5432/${value("POSTGRES_DB") ?: "helium"}",
                    username = value("HELIUM_DB_USER") ?: value("POSTGRES_USER") ?: "helium",
                    password = value("HELIUM_DB_PASSWORD") ?: value("POSTGRES_PASSWORD") ?: "",
                    maxPoolSize = number("HELIUM_DB_POOL_SIZE", 10, "HELIUM_DB_MAX_POOL_SIZE"),
                    migrateOnStart = flag("HELIUM_MIGRATE_ON_START", !environment.isProduction),
                ),
                redisUrl = value("HELIUM_REDIS_URL"),

                dataKeysBase64 = required("HELIUM_DATA_KEYS"),
                dataKeyVersion = number("HELIUM_DATA_KEY_VERSION", 1),
                tokenHmacKeyBase64 = required("HELIUM_TOKEN_HMAC_KEY"),
                passwordPepperBase64 = value("HELIUM_PASSWORD_PEPPER"),
                passwordPepperVersion = number("HELIUM_PASSWORD_PEPPER_VERSION", 1),

                argon2 = PasswordHashParameters(
                    // Concept §4.1 says to benchmark these in the deployment environment; the
                    // defaults are its starting point, not a recommendation to leave them alone.
                    memoryKib = number("HELIUM_ARGON2_MEMORY_KIB", 64 * 1024),
                    iterations = number("HELIUM_ARGON2_ITERATIONS", 3),
                    parallelism = number("HELIUM_ARGON2_PARALLELISM", 2),
                    saltLength = 16,
                    hashLength = 32,
                    pepperVersion = if (value("HELIUM_PASSWORD_PEPPER") != null) {
                        number("HELIUM_PASSWORD_PEPPER_VERSION", 1)
                    } else {
                        0
                    },
                ),
                // Bounds concurrent hashing: memoryKib × this is the worst-case heap it holds.
                argon2Parallelism = number("HELIUM_ARGON2_CONCURRENCY", 4),

                lifetimes = Lifetimes(
                    accessToken = Duration.ofMinutes(number("HELIUM_ACCESS_TOKEN_MINUTES", 5).toLong()),
                    sessionIdle = Duration.ofHours(number("HELIUM_SESSION_IDLE_HOURS", 12).toLong()),
                    sessionAbsolute = Duration.ofDays(number("HELIUM_SESSION_ABSOLUTE_DAYS", 7).toLong()),
                    refreshTokenInactivity = Duration.ofDays(number("HELIUM_REFRESH_IDLE_DAYS", 30).toLong()),
                    refreshTokenAbsolute = Duration.ofDays(number("HELIUM_REFRESH_ABSOLUTE_DAYS", 90).toLong()),
                ),
                mfaPolicy = MfaPolicy.entries
                    .firstOrNull { it.name.equals(value("HELIUM_MFA_POLICY"), ignoreCase = true) }
                    ?: MfaPolicy.OPTIONAL,

                mail = mail,
                google = providerCredentials("GOOGLE"),
                github = providerCredentials("GITHUB"),
                discord = providerCredentials("DISCORD"),
                bootstrapAdmin = bootstrapAdmin,
            )
        }
    }
}
