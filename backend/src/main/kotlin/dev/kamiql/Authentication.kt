package dev.kamiql

import dev.kamiql.domain.auth.OAuthProvider
import dev.kamiql.domain.session.UserSession
import dev.kamiql.domain.user.User
import io.github.cdimascio.dotenv.Dotenv
import io.ktor.client.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.util.*
import kotlinx.serialization.Serializable
import org.koin.ktor.ext.inject
import java.util.UUID

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
val pending = mutableMapOf<UUID, UserSession>()

@Serializable
enum class PasswordRequirement(val regex: Regex, val description: String) {
    LENGTH("^.{8,32}$".toRegex(), "Between 8 - 32 characters"),
    LETTERS("[Z-a]".toRegex(), "Contains small and capital letters"),
    NUMBER("[0-9]".toRegex(), "Contains numbers"),
    SPECIAL_CHARACTER("[^A-Za-z0-9]".toRegex(), "Contains special characters"),
}

fun String.checkPasswordRequirements(): Map<PasswordRequirement, Boolean> {
    return PasswordRequirement.entries.associateWith { it.regex.containsMatchIn(this) }
}