package dev.kamiql.routes

import dev.kamiql.PasswordRequirement
import dev.kamiql.Router
import dev.kamiql.domain.api.auth.PasswordRequirementResponse
import dev.kamiql.domain.security.Permission
import dev.kamiql.storage.RoleRepository
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get
import io.ktor.server.routing.route

object DataRoutes : Router {
    override fun Routing.routes() {
        route("/data") {
            get("/passwordRequirements") {
                call.respond(
                    PasswordRequirement.entries.associate {
                        it.name to PasswordRequirementResponse(
                            regex = it.regex.pattern,
                            description = it.description
                        )
                    }
                )
            }

            get("/permissions") {
                call.respond(
                    Permission.entries.toList()
                )
            }

            get("/roles") {
                call.respond(
                    RoleRepository.findAll().values.toList()
                )
            }
        }
    }
}