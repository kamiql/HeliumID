package dev.kamiql.routes

import dev.kamiql.Router
import dev.kamiql.UserAttributeKey
import dev.kamiql.domain.api.auth.ResetPasswordRequest
import dev.kamiql.domain.api.user.EditUserInformation
import dev.kamiql.domain.auth.OAuthProvider
import dev.kamiql.domain.session.UserSession
import dev.kamiql.domain.user.Email
import dev.kamiql.middleware.UserMiddleware
import dev.kamiql.middleware.middleware
import dev.kamiql.services.BCryptService
import dev.kamiql.services.VerificationType
import dev.kamiql.services.verify
import dev.kamiql.storage.CredentialRepository
import dev.kamiql.storage.UserRepository
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import org.koin.core.component.KoinComponent

object UserRoutes : Router, KoinComponent {
    override fun Routing.routes() {
        route("/user") {
            middleware {
                register(UserMiddleware)
            }

            route("/email") {
                post("/verify") {
                    val user = call.attributes[UserAttributeKey]

                    return@post verify(VerificationType.EMAIL) {
                        UserRepository[user.id] = user.copy(emailVerified = true)
                    }
                }
            }

            route("/password") {
                post("/reset") {

                }

                post("/change") {
                    val user = call.attributes[UserAttributeKey]

                    val req = call.receive<ResetPasswordRequest>()

                    if (!BCryptService.verify(req.old, user.credentials().passwordHash)) {
                        return@post call.respond(HttpStatusCode.Unauthorized)
                    }

                    CredentialRepository[user.id] = user.credentials().copy(
                        passwordHash = BCryptService.hash(req.new)
                    )

                    call.sessions.clear<UserSession>()
                    call.respond(HttpStatusCode.OK)
                }
            }

            route("/oauth2") {
                route("/{provider}") {
                    post("/remove") {
                        val user = call.attributes[UserAttributeKey]
                        val provider = OAuthProvider.entries.find {
                            it.name.lowercase() == (call.parameters["provider"] ?: return@post call.respond(
                                HttpStatusCode.BadRequest
                            ))
                        }
                        val credentials = user.credentials()

                        CredentialRepository[user.id] = credentials.apply {
                            accounts.remove(provider)
                        }

                        UserRepository[user.id] = user.apply {
                            linkedAccounts.remove(provider)
                        }

                        call.respond(HttpStatusCode.OK)
                    }
                }
            }

            route("/@me") {
                get {
                    val user = call.attributes[UserAttributeKey]
                    call.respond(HttpStatusCode.OK, user)
                }

                post {
                    val user = call.attributes[UserAttributeKey]
                    val req = call.receive<EditUserInformation>()

                    val new = user.copy(
                        username = req.username ?: user.username,
                        firstName = req.firstName ?: user.firstName,
                        lastName = req.lastName ?: user.lastName,
                        email = req.email?.let(::Email) ?: user.email,
                        emailVerified = if (req.email != null && req.email != user.email.value) {
                            false
                        } else {
                            user.emailVerified
                        },
                        username_lower = req.username?.lowercase() ?: user.username,
                    )

                    if (req.email != null && req.email != user.email.value) {
                        return@post verify(VerificationType.EMAIL) {
                            UserRepository[user.id] = new
                        }
                    }

                    UserRepository[user.id] = new
                    call.respond(HttpStatusCode.OK)
                }
            }
        }
    }
}