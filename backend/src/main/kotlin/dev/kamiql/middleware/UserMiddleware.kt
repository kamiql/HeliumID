package dev.kamiql.middleware

import dev.kamiql.UserAttributeKey
import dev.kamiql.domain.session.UserSession
import dev.kamiql.storage.UserRepository
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.sessions.*

object UserMiddleware : Middleware {
    override suspend fun execute(call: ApplicationCall): MiddlewareResult {
        val session = call.sessions.get<UserSession>() ?: return MiddlewareResult.Block(HttpStatusCode.Unauthorized)
        val user = UserRepository[session.userId] ?: return MiddlewareResult.Block(HttpStatusCode.NotFound)

        call.attributes.put(UserAttributeKey, user)
        return MiddlewareResult.Pass
    }
}