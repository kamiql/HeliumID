package dev.kamiql.routes

import dev.kamiql.Router
import dev.kamiql.services.VerificationManager
import dev.kamiql.services.VerificationStatus
import dev.kamiql.services.VerificationType
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.util.*

object VerificationRoutes : Router {
    override fun Routing.routes() {
        route("/verification") {
            post {
                val id = call.queryParameters["id"]
                    ?.let(UUID::fromString)
                    ?: return@post call.respond(HttpStatusCode.BadRequest)

                val type = call.queryParameters["type"]
                    ?.let {
                        runCatching {
                            VerificationType.valueOf(it.uppercase())
                        }.getOrNull()
                    }
                    ?: return@post call.respond(HttpStatusCode.BadRequest)

                val secret = call.queryParameters["secret"]
                    ?: return@post call.respond(HttpStatusCode.BadRequest)

                val confirmed = VerificationManager.confirm(
                    id = id,
                    type = type,
                    secret = secret
                )

                if (!confirmed) {
                    return@post call.respond(HttpStatusCode.BadRequest)
                }

                call.respond(HttpStatusCode.OK)
            }

            get("/completed") {
                val id = call.queryParameters["id"]
                    ?.let(UUID::fromString)
                    ?: return@get call.respond(HttpStatusCode.BadRequest)

                when (VerificationManager.status(id)) {
                    VerificationStatus.PENDING ->
                        call.respond(HttpStatusCode.Accepted)

                    VerificationStatus.COMPLETED ->
                        call.respond(HttpStatusCode.OK)

                    VerificationStatus.EXPIRED ->
                        call.respond(HttpStatusCode.Gone)

                    VerificationStatus.NOT_FOUND ->
                        call.respond(HttpStatusCode.NotFound)
                }
            }
        }
    }
}