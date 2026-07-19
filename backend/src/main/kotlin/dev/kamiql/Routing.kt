package dev.kamiql

import dev.kamiql.routes.AdminRoutes
import dev.kamiql.routes.AuthRoutes
import dev.kamiql.routes.DataRoutes
import dev.kamiql.routes.UserRoutes
import dev.kamiql.routes.VerificationRoutes
import io.ktor.server.application.*
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.routing.*

interface Router {
    fun Routing.routes()
}

fun Application.routing() {
    routing {
        listOf(
            AuthRoutes,
            UserRoutes,
            VerificationRoutes,
            AdminRoutes,
            DataRoutes,
        ).forEach { router ->
            with(router) {
                routes()
            }
        }
    }
}