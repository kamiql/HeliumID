package dev.kamiql.routes

import dev.kamiql.Router
import dev.kamiql.checkPasswordRequirements
import dev.kamiql.domain.api.auth.CreateUserRequest
import dev.kamiql.domain.api.auth.LoginUserRequest
import dev.kamiql.domain.api.auth.RequireMFAResponse
import dev.kamiql.domain.auth.Credentials
import dev.kamiql.domain.auth.OAuthData
import dev.kamiql.domain.auth.OAuthProvider
import dev.kamiql.domain.session.UserSession
import dev.kamiql.domain.user.Account
import dev.kamiql.domain.user.Email
import dev.kamiql.domain.user.User
import dev.kamiql.middleware.middleware
import dev.kamiql.middleware.types.EmailVerificationMiddleware
import dev.kamiql.pending
import dev.kamiql.redirects
import dev.kamiql.services.BCryptService
import dev.kamiql.storage.CredentialRepository
import dev.kamiql.storage.UserRepository
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import java.util.*

object AuthRoutes : Router {
    override fun Routing.routes() {
        route("/auth") {
            post("/register") {
                val req = call.receive<CreateUserRequest>()

                if (UserRepository.existsBy("username_lower", req.username)) {
                    return@post call.respond(
                        HttpStatusCode.Conflict,
                        "Username already exists"
                    )
                }

                if (UserRepository.existsBy("email", req.email.value)) {
                    return@post call.respond(
                        HttpStatusCode.Conflict,
                        "Email already exists"
                    )
                }

                req.password.checkPasswordRequirements().filter { !it.value }.takeIf { it.isNotEmpty() }?.let {
                    return@post call.respond(HttpStatusCode.Conflict, it)
                }

                val user = User(
                    UUID.randomUUID(),
                    req.username,
                    req.username.lowercase(),
                    req.firstName,
                    req.lastName,
                    Email(req.email.value),
                )

                UserRepository[user.id] = user
                CredentialRepository[user.id] = Credentials(
                    passwordHash = BCryptService.hash(req.password),
                    mutableMapOf()
                )

                call.sessions.set(UserSession(UUID.randomUUID(), user.id))
                call.respond(HttpStatusCode.Created, user)
            }

            post("/login") {
                val req = call.receive<LoginUserRequest>()

                val user = UserRepository.findBy("email", req.email) ?: return@post call.respond(
                    HttpStatusCode.Unauthorized,
                    "Invalid credentials"
                )

                val credentials = CredentialRepository[user.id] ?: return@post call.respond(
                    HttpStatusCode.Unauthorized,
                    "Invalid credentials"
                )

                if (!BCryptService.verify(req.password, credentials.passwordHash)) {
                    return@post call.respond(
                        HttpStatusCode.Unauthorized,
                        "Invalid credentials"
                    )
                }

                if (user.requireMFA()) {
                    pending[user.id] = UserSession(
                        UUID.randomUUID(),
                        user.id
                    )

                    return@post call.respond(
                        HttpStatusCode.Accepted,
                        RequireMFAResponse(
                            user.id,
                            user.mfaMethods()
                        )
                    )
                }

                call.sessions.set(
                    UserSession(
                        UUID.randomUUID(),
                        user.id
                    )
                )

                call.respond(HttpStatusCode.OK)
            }

            post("/logout") {
                call.sessions.clear<UserSession>()
                call.respond(HttpStatusCode.OK)
            }

            route("/oauth2") {
                middleware {
                    register(EmailVerificationMiddleware)
                }

                OAuthProvider.entries.toList().forEach { provider ->
                    route(provider.name.lowercase()) {
                        authenticate("${provider.name.lowercase()}-oauth") {
                            get("/login") {}

                            get("/callback") {
                                call.principal<OAuthAccessTokenResponse.OAuth2>()?.let { principal ->
                                    val state = principal.state ?: return@let

                                    val userInfo = provider.userInfo(principal.accessToken)

                                    call.sessions.get<UserSession>()?.let session@{ session ->
                                        if (CredentialRepository.findUserByOAuth(
                                            provider,
                                            userInfo.id
                                        )?.let { UserRepository[it] }?.id == session.userId) {
                                            redirects.remove(state)?.let { redirect ->
                                                call.respondRedirect(redirect)
                                            }
                                            return@get
                                        }

                                        val user = UserRepository[session.userId] ?: return@session
                                        val credentials = user.credentials()

                                        CredentialRepository[user.id] = credentials.apply {
                                            accounts[provider] = OAuthData(
                                                provider,
                                                userInfo.id,
                                                principal.accessToken,
                                                principal.refreshToken,
                                            )
                                        }

                                        UserRepository[user.id] = user.apply {
                                            linkedAccounts[provider] = Account(
                                                userInfo.id,
                                                userInfo.email,
                                                userInfo.username,
                                            )
                                        }

                                        redirects.remove(state)?.let { redirect ->
                                            call.respondRedirect(redirect)
                                            return@get
                                        }

                                        return@let
                                    }

                                    val uuid = CredentialRepository.findUserByOAuth(
                                        provider,
                                        userInfo.id
                                    ) ?: run {
                                        redirects.remove(state)
                                        return@get call.respondRedirect("/login?error=account+not+linked")
                                    }

                                    call.sessions.set(UserSession(
                                        UUID.randomUUID(),
                                        uuid
                                    ))

                                    redirects.remove(state)?.let { redirect ->
                                        call.respondRedirect(redirect)
                                        return@get
                                    }
                                }

                                call.respondRedirect("/")
                            }
                        }
                    }
                }
            }
        }
    }
}