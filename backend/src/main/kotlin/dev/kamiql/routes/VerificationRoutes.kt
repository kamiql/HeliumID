package dev.kamiql.routes

import dev.kamiql.Router
import dev.kamiql.domain.api.auth.MFARequest
import dev.kamiql.domain.session.MFASession
import dev.kamiql.pending
import dev.kamiql.services.VerificationManager
import dev.kamiql.services.VerificationType
import dev.kamiql.storage.UserRepository
import io.ktor.http.*
import io.ktor.server.request.receive
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import java.util.*

object VerificationRoutes : Router {
    override fun Routing.routes() {
        route("/verification") {

            post("/create") {
                val req = call.receive<MFARequest>()

                val user = UserRepository[req.userId] ?: return@post call.respond(HttpStatusCode.BadRequest)

                val id = VerificationManager.create(
                    user,
                    req.type
                ) { call ->
                    pending.remove(user.id)?.let { pending ->
                        call.sessions.set(pending)
                    }

                    call.sessions.set(MFASession(
                        req.userId,
                        UUID.randomUUID(),
                        req.type
                    ))
                }

                call.respond(HttpStatusCode.OK, id)
            }

            post {
                val id = call.queryParameters["id"]
                    ?.let { runCatching { UUID.fromString(it) }.getOrNull() }
                    ?: return@post call.respond(HttpStatusCode.BadRequest)

                val code = call.queryParameters["code"]
                    ?: return@post call.respond(HttpStatusCode.BadRequest)

                if (!code.matches(Regex("\\d{6}"))) {
                    return@post call.respond(HttpStatusCode.BadRequest)
                }

                val confirmed = VerificationManager.confirm(
                    call = call,
                    id = id,
                    code = code
                )

                if (!confirmed) {
                    return@post call.respond(HttpStatusCode.BadRequest)
                }

                call.respond(HttpStatusCode.OK)
            }
        }
    }
}