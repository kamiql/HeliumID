package dev.kamiql

import dev.kamiql.domain.auth.OAuthProvider
import dev.kamiql.domain.user.User
import io.github.cdimascio.dotenv.Dotenv
import io.ktor.client.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.util.*
import org.koin.ktor.ext.inject

fun Application.authentication() {
    val dotenv: Dotenv by inject()
    val httpClient: HttpClient by inject()

    install(Authentication) {
        OAuthProvider.entries.toList().forEach { type ->
            oauth("${type.name.lowercase()}-oauth") {
                urlProvider = { "${dotenv["HOST_URL"]}/api/auth/oauth2/${type.name.lowercase()}/callback" }
                client = httpClient
                settings = type.settings
            }
        }
    }
}

val UserAttributeKey = AttributeKey<User>("UserAttributeKey")

val redirects = mutableMapOf<String, String>()