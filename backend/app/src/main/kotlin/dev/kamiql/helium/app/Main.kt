package dev.kamiql.helium.app

import dev.kamiql.helium.api.heliumRoutes
import dev.kamiql.helium.api.installHealthRoutes
import dev.kamiql.helium.api.installHeliumPlugins
import dev.kamiql.helium.persistence.DatabaseConfig
import dev.kamiql.helium.persistence.HeliumDatabase
import io.ktor.server.application.Application
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.routing.routing
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import kotlin.system.exitProcess

private val log = LoggerFactory.getLogger("dev.kamiql.helium.app.Main")

/**
 * Entry point.
 *
 * The same image runs as an API server, a background worker, or both, selected by
 * `HELIUM_ROLE`. Splitting them in production keeps a slow mail server from competing with
 * request handling for threads, and lets the two scale independently.
 */
fun main() {
    val config = try {
        HeliumConfig.fromEnvironment().also { it.validate() }
    } catch (error: Exception) {
        // A configuration problem must be obvious and fatal. Starting with a broken key
        // configuration would mean discovering it when the first user tries to sign in.
        log.error("failed to start: {}", error.message)
        exitProcess(78) // EX_CONFIG
    }

    log.info(
        "starting HeliumID env={} role={} issuer={} secureCookies={}",
        config.environment, config.role, config.issuerUrl, config.secureCookies,
    )

    if (config.role == HeliumRole.MIGRATE) {
        // One-shot migration runner. Applies pending migrations and exits, so a release
        // pipeline can gate schema changes independently of rolling out application code.
        HeliumDatabase.migrateOnly(
            DatabaseConfig(
                jdbcUrl = config.database.jdbcUrl,
                username = config.database.username,
                password = config.database.password,
            ),
        )
        log.info("migrations complete")
        exitProcess(0)
    }

    val components = HeliumComponents(config)
    val background = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    Runtime.getRuntime().addShutdownHook(
        Thread {
            log.info("shutting down")
            background.cancel()
            components.close()
        },
    )

    runBlocking {
        // Generate the first signing key before serving traffic, so the first token request
        // does not race several instances into creating one each.
        components.warmUp()

        if (config.environment == HeliumEnvironment.DEV) {
            DevBootstrap(components, config).run()
        }
    }

    if (config.role != HeliumRole.API) {
        components.outboxDispatcher.start(background)
        components.maintenanceJobs.start(background)
        log.info("background workers started")
    }

    if (config.role == HeliumRole.WORKER) {
        // Worker-only: no HTTP surface at all beyond keeping the process alive.
        log.info("running as worker only; no HTTP listener")
        runBlocking { kotlinx.coroutines.awaitCancellation() }
    }

    embeddedServer(Netty, port = config.port, host = config.bindHost) {
        heliumModule(components, config)
    }.start(wait = true)
}

/** Wires the Ktor application. Separate from [main] so tests can start it in-process. */
fun Application.heliumModule(components: HeliumComponents, config: HeliumConfig) {
    installHeliumPlugins(components.httpSecurity)
    installHealthRoutes { components.isReady() }

    routing {
        heliumRoutes(components.apiDependencies)
    }

    log.info("HeliumID listening on port {}", config.port)
}
