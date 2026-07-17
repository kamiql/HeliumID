package dev.kamiql.middleware

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.util.*

class RouteMiddlewareConfig {
    internal val middlewares = mutableListOf<Middleware>()

    fun register(middleware: Middleware) {
        middlewares += middleware
    }
}

fun Route.middleware(configure: RouteMiddlewareConfig.() -> Unit = {}) = install(createRouteScopedPlugin("middleware-${UUID.randomUUID()}", ::RouteMiddlewareConfig) {
    on(AuthenticationChecked) { call ->
        pluginConfig.middlewares.forEach { middleware ->
            when (val res = middleware.execute(call)) {
                is MiddlewareResult.Pass -> return@forEach
                is MiddlewareResult.Block -> {
                    call.respond(res.status, res.message ?: "Forbidden")
                    return@on
                }
            }
        }
    }
}, configure)