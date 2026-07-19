package dev.kamiql

import dev.kamiql.domain.session.MFASession
import dev.kamiql.domain.session.UserSession
import dev.kamiql.serializer.session.MFASessionSerializer
import dev.kamiql.serializer.session.UserSessionSerializer
import dev.kamiql.storage.CookieSessionRepository
import io.ktor.server.application.*
import io.ktor.server.sessions.*

fun Application.sessions() {
    install(Sessions) {
        cookie<UserSession>("user_session", CookieSessionRepository) {
            serializer = UserSessionSerializer
            cookie.path = "/"
            cookie.extensions["SameSite"] = "lax"
            cookie.maxAgeInSeconds = 7776000
        }

        cookie<MFASession>("mfa_session") {
            serializer = MFASessionSerializer
            cookie.path = "/"
            cookie.extensions["SameSite"] = "lax"
            cookie.maxAgeInSeconds = 1800
        }
    }
}