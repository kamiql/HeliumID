package dev.kamiql.routes

import dev.kamiql.Router
import dev.kamiql.domain.security.Permission
import dev.kamiql.middleware.middleware
import dev.kamiql.middleware.types.PermissionMiddleware
import io.ktor.server.routing.*

object AdminRoutes : Router {
    override fun Routing.routes() {
        route("/admin") {
            middleware {
                register(PermissionMiddleware(listOf(Permission.ADMINISTRATOR)))
            }


        }
    }
}