package dev.kamiql.helium.testing

import dev.kamiql.helium.persistence.DatabaseConfig
import dev.kamiql.helium.persistence.HeliumDatabase
import org.jetbrains.exposed.v1.jdbc.Database
import org.testcontainers.containers.PostgreSQLContainer

/**
 * A real PostgreSQL instance for integration tests.
 *
 * Testcontainers rather than H2. The whole point of these tests is the behaviour that only a
 * real database has: partial unique indexes, `timestamptz` semantics, constraint violations
 * surfacing as the exception the repositories catch, and conditional UPDATEs racing under
 * genuine concurrency. An in-memory substitute would pass while production failed.
 *
 * The container is started once for the whole JVM and shared; each test class truncates what
 * it needs. Starting a container per class would add minutes to the suite for no isolation
 * benefit that truncation does not already provide.
 */
object PostgresFixture {

    /**
     * Pinned to the major version production runs, because the features under test — partial
     * indexes, `ON CONFLICT`, `timestamptz` — have version-dependent edge cases.
     */
    private const val IMAGE = "postgres:17-alpine"

    val container: PostgreSQLContainer<*> by lazy {
        PostgreSQLContainer(IMAGE)
            .withDatabaseName("helium_test")
            .withUsername("helium")
            .withPassword("helium")
            // Reuse across runs when the developer has opted in via ~/.testcontainers.properties.
            .withReuse(true)
            .also { it.start() }
    }

    /**
     * A migrated database.
     *
     * Migrations run through Flyway exactly as they do in production, so a broken migration
     * fails the suite rather than being papered over by a schema generated from the Exposed
     * table definitions. That divergence is precisely what these tests exist to catch.
     */
    val database: HeliumDatabase by lazy {
        HeliumDatabase.connect(
            DatabaseConfig(
                jdbcUrl = container.jdbcUrl,
                username = container.username,
                password = container.password,
                maxPoolSize = 8,
                migrateOnStart = true,
            ),
        )
    }

    val db: Database get() = database.database

    /**
     * Empties every table that holds test data, in dependency order.
     *
     * `roles`, `role_permissions` and `oauth_scopes` are deliberately spared: they are
     * reference data seeded by `V2__reference_data.sql`, and truncating them would make every
     * subsequent test fail on a missing foreign key.
     */
    fun truncateAll() {
        container.createConnection("").use { connection ->
            connection.createStatement().use { statement ->
                statement.execute(
                    """
                    TRUNCATE TABLE
                        audit_logs, outbox_events, idempotency_records,
                        refresh_tokens, refresh_token_families, revoked_access_tokens,
                        authorization_codes, consents,
                        oauth_client_scopes, oauth_redirect_uris, oauth_clients,
                        signing_keys,
                        recovery_codes, totp_factors, mfa_factors, webauthn_credentials,
                        verification_tokens, sessions, external_identities,
                        password_credentials, user_roles, users
                    RESTART IDENTITY CASCADE
                    """.trimIndent(),
                )
            }
        }
    }
}
