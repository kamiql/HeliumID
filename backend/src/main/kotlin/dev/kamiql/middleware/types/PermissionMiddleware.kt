package dev.kamiql.middleware.types

import dev.kamiql.UserAttributeKey
import dev.kamiql.domain.security.Permission
import dev.kamiql.middleware.Middleware
import dev.kamiql.middleware.MiddlewareResult
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall

class PermissionMiddleware(
    val require: List<Permission>
) : Middleware {
    override val priority: Int = 5

    override suspend fun execute(call: ApplicationCall): MiddlewareResult {
        val user = call.attributes[UserAttributeKey]

        if (require.none { user.roles().flatMap { it.permissions }.contains(it) })
            return MiddlewareResult.Block(HttpStatusCode.Unauthorized, "Missing permission")

        return MiddlewareResult.Pass
    }
}