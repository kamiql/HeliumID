package dev.kamiql.middleware

import io.ktor.server.application.*

fun interface Middleware {
    suspend fun execute(call: ApplicationCall): MiddlewareResult
}