package dev.kamiql.middleware

import io.ktor.http.*

sealed class MiddlewareResult {
    data object Pass : MiddlewareResult()
    data class Block(val status: HttpStatusCode = HttpStatusCode.Forbidden, val message: String? = null) : MiddlewareResult()
}