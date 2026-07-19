package dev.kamiql.middleware.types

import dev.kamiql.domain.session.UserSession
import dev.kamiql.middleware.Middleware
import dev.kamiql.middleware.MiddlewareResult
import dev.kamiql.storage.UserRepository
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions

object EmailVerificationMiddleware : Middleware {
    override val priority: Int = 1

    override suspend fun execute(call: ApplicationCall): MiddlewareResult {
        val session = call.sessions.get<UserSession>() ?: return MiddlewareResult.Pass
        val user = UserRepository[session.userId] ?: return MiddlewareResult.Pass

        if (!user.emailVerified) return MiddlewareResult.Block(
            HttpStatusCode.Unauthorized,
            "Email not verified"
        )

        return MiddlewareResult.Pass
    }
}