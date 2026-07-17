package dev.kamiql.middleware.types

import dev.kamiql.UserAttributeKey
import dev.kamiql.middleware.Middleware
import dev.kamiql.middleware.MiddlewareResult
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall

object EmailVerificationMiddleware : Middleware {
    override val priority: Int = 1

    override suspend fun execute(call: ApplicationCall): MiddlewareResult {
        val user = call.attributes[UserAttributeKey]

        if (!user.emailVerified) return MiddlewareResult.Block(
            HttpStatusCode.Unauthorized,
            "Email not verified"
        )

        return MiddlewareResult.Pass
    }
}