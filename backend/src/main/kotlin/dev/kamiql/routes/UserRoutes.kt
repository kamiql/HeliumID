package dev.kamiql.routes

import dev.kamiql.Router
import dev.kamiql.UserAttributeKey
import dev.kamiql.checkPasswordRequirements
import dev.kamiql.domain.api.auth.ResetPasswordRequest
import dev.kamiql.domain.api.user.EditUserInformationRequest
import dev.kamiql.domain.auth.OAuthProvider
import dev.kamiql.domain.auth.TotpRequest
import dev.kamiql.domain.security.Permission
import dev.kamiql.domain.security.Role
import dev.kamiql.domain.session.UserSession
import dev.kamiql.domain.user.Email
import dev.kamiql.domain.user.User
import dev.kamiql.middleware.types.UserMiddleware
import dev.kamiql.middleware.middleware
import dev.kamiql.middleware.types.EmailVerificationMiddleware
import dev.kamiql.services.BCryptService
import dev.kamiql.services.TotpService
import dev.kamiql.services.VerificationType
import dev.kamiql.services.verify
import dev.kamiql.storage.CredentialRepository
import dev.kamiql.storage.RoleRepository
import dev.kamiql.storage.UserRepository
import dev.samstevens.totp.code.DefaultCodeGenerator
import dev.samstevens.totp.code.DefaultCodeVerifier
import dev.samstevens.totp.qr.QrData
import dev.samstevens.totp.qr.ZxingPngQrGenerator
import dev.samstevens.totp.secret.DefaultSecretGenerator
import dev.samstevens.totp.time.SystemTimeProvider
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.respond
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.encodeBase64
import org.koin.core.component.KoinComponent
import java.util.UUID

object UserRoutes : Router, KoinComponent {
    override fun Routing.routes() {
        route("/user") {
            middleware {
                register(UserMiddleware)
            }

            post("/delete") {
                val user = call.attributes[UserAttributeKey]
                call.sessions.clear<UserSession>()
                UserRepository.delete(user.id)
                CredentialRepository.delete(user.id)
                call.respond(HttpStatusCode.NoContent)
            }

            route("/email") {
                post("/verify") {
                    val user = call.attributes[UserAttributeKey]

                    return@post verify(VerificationType.EMAIL, user.id) {
                        UserRepository[user.id] = user.copy(emailVerified = true)
                    }
                }
            }

            route("/totp") {
                middleware {
                    register(EmailVerificationMiddleware)
                }

                post("/setup") {
                    val user = call.attributes[UserAttributeKey]
                    val credentials = user.credentials()

                    if (user.totpEnabled) {
                        return@post call.respond(HttpStatusCode.Conflict)
                    }

                    val secret = TotpService.generateSecret()

                    CredentialRepository[user.id] = credentials.copy(
                        totpSecret = secret
                    )

                    call.respond(
                        HttpStatusCode.OK,
                        mapOf(
                            "secret" to secret,
                            "qrCode" to TotpService.generateQrCode(
                                secret = secret,
                                label = user.email.value
                            )
                        )
                    )
                }

                post("/enable") {
                    val user = call.attributes[UserAttributeKey]
                    val credentials = user.credentials()

                    val secret = credentials.totpSecret
                        ?: return@post call.respond(HttpStatusCode.BadRequest)

                    val request = call.receive<TotpRequest>()

                    if (!TotpService.verify(secret, request.code)) {
                        return@post call.respond(HttpStatusCode.Unauthorized)
                    }

                    UserRepository[user.id] = user.copy(
                        totpEnabled = true
                    )

                    call.respond(HttpStatusCode.OK)
                }

                post("/disable") {
                    val user = call.attributes[UserAttributeKey]
                    val credentials = user.credentials()

                    if (!user.totpEnabled) {
                        return@post call.respond(HttpStatusCode.Conflict)
                    }

                    val request = call.receive<TotpRequest>()
                    val secret = credentials.totpSecret
                        ?: return@post call.respond(HttpStatusCode.BadRequest)

                    if (!TotpService.verify(secret, request.code)) {
                        return@post call.respond(HttpStatusCode.Unauthorized)
                    }

                    CredentialRepository[user.id] = credentials.copy(
                        totpSecret = null
                    )

                    UserRepository[user.id] = user.copy(
                        totpEnabled = false
                    )

                    call.respond(HttpStatusCode.OK)
                }
            }

            route("/password") {
                middleware {
                    register(EmailVerificationMiddleware)
                }

                post("/reset") {

                }

                post("/change") {
                    val user = call.attributes[UserAttributeKey]

                    val req = call.receive<ResetPasswordRequest>()

                    if (!BCryptService.verify(req.old, user.credentials().passwordHash)) {
                        return@post call.respond(HttpStatusCode.Unauthorized)
                    }

                    req.new.checkPasswordRequirements().filter { !it.value }.takeIf { it.isNotEmpty() }?.let {
                        return@post call.respond(HttpStatusCode.Conflict, it)
                    }

                    CredentialRepository[user.id] = user.credentials().copy(
                        passwordHash = BCryptService.hash(req.new)
                    )

                    call.sessions.clear<UserSession>()
                    call.respond(HttpStatusCode.OK)
                }
            }

            route("/oauth2") {
                middleware {
                    register(EmailVerificationMiddleware)
                }

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
                    val req = call.receive<EditUserInformationRequest>()

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
                        return@post verify(VerificationType.EMAIL, user.id) {
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