package dev.kamiql.middleware.types

import dev.kamiql.UserAttributeKey
import dev.kamiql.domain.session.UserSession
import dev.kamiql.middleware.Middleware
import dev.kamiql.middleware.MiddlewareResult
import dev.kamiql.storage.UserRepository
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions

object UserMiddleware : Middleware {
    override val priority: Int = 10

    override suspend fun execute(call: ApplicationCall): MiddlewareResult {
        val session = call.sessions.get<UserSession>() ?: return MiddlewareResult.Block(HttpStatusCode.Unauthorized)
        val user = UserRepository[session.userId] ?: return MiddlewareResult.Block(HttpStatusCode.NotFound)

        call.attributes.put(UserAttributeKey, user)
        return MiddlewareResult.Pass
    }
}