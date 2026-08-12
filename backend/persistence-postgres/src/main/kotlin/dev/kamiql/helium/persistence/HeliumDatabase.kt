package dev.kamiql.helium.persistence

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import javax.sql.DataSource

/**
 * Connection pool, migrations and the Exposed [Database] handle.
 *
 * @param maxPoolSize must be sized against the database's own connection limit *and* against
 *        the number of application instances. Password hashing already bounds concurrency
 *        elsewhere; an oversized pool here just moves the queue into the database.
 */
data class DatabaseConfig(
    val jdbcUrl: String,
    val username: String,
    val password: String,
    val maxPoolSize: Int = 10,
    val connectionTimeoutMs: Long = 5_000,
    /**
     * Whether to run Flyway at boot.
     *
     * Dev and test do; production defaults to `false` so migrations are a deliberate,
     * gated step in the release process rather than a side effect of a pod restarting
     * (concept §3.4).
     */
    val migrateOnStart: Boolean = false,
)

class HeliumDatabase private constructor(
    val dataSource: HikariDataSource,
    val database: Database,
) : AutoCloseable {

    override fun close() = dataSource.close()

    companion object {
        private val log = LoggerFactory.getLogger(HeliumDatabase::class.java)

        fun connect(config: DatabaseConfig): HeliumDatabase {
            val hikari = HikariConfig().apply {
                jdbcUrl = config.jdbcUrl
                username = config.username
                password = config.password
                maximumPoolSize = config.maxPoolSize
                connectionTimeout = config.connectionTimeoutMs
                // Read committed is enough: every check-then-act sequence in this codebase is
                // written as a single conditional UPDATE, so it does not rely on isolation.
                transactionIsolation = "TRANSACTION_READ_COMMITTED"
                isAutoCommit = false
                poolName = "helium-pool"
            }
            val dataSource = HikariDataSource(hikari)

            if (config.migrateOnStart) {
                migrate(dataSource)
            } else {
                log.info("skipping migrations at startup; run them as an explicit release step")
            }

            return HeliumDatabase(dataSource, Database.connect(dataSource))
        }

        /**
         * Applies pending migrations and closes the pool.
         *
         * For the one-shot migration runner (`HELIUM_ROLE=migrate`), which exists so a release
         * pipeline can gate schema changes rather than have them happen whenever a pod
         * restarts (concept §3.4).
         */
        fun migrateOnly(config: DatabaseConfig) {
            val hikari = HikariConfig().apply {
                jdbcUrl = config.jdbcUrl
                username = config.username
                password = config.password
                // A migration is a single connection's worth of work.
                maximumPoolSize = 2
                poolName = "helium-migrate"
            }
            HikariDataSource(hikari).use { migrate(it) }
        }

        /**
         * Applies pending migrations.
         *
         * `baselineOnMigrate` is deliberately off: pointing this at a non-empty database that
         * Flyway does not know about should fail loudly, not silently assume the schema is
         * already correct.
         */
        fun migrate(dataSource: DataSource) {
            val result = Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .baselineOnMigrate(false)
                .validateOnMigrate(true)
                .load()
                .migrate()
            log.info("applied {} migration(s), schema now at {}", result.migrationsExecuted, result.targetSchemaVersion)
        }
    }
}

// --- time conversions --------------------------------------------------------
//
// The domain speaks `Instant`; Exposed's `timestamptz` column type speaks `OffsetDateTime`.
// These two helpers are the only place the conversion happens, and both pin UTC so a JVM
// default zone can never leak into stored data.

internal fun Instant.toDb(): OffsetDateTime = atOffset(ZoneOffset.UTC)

internal fun OffsetDateTime.toInstantUtc(): Instant = toInstant()
