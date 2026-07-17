package dev.kamiql.middleware

import io.ktor.server.application.*

interface Middleware {
    val priority: Int
    suspend fun execute(call: ApplicationCall): MiddlewareResult
}