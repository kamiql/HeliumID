package dev.kamiql.domain.auth

import dev.kamiql.redirects
import io.github.cdimascio.dotenv.Dotenv
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.auth.*
import kotlinx.serialization.Serializable
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

data class OAuthUserInfo(
    val id: String,
    val email: String,
    val username: String
)

enum class OAuthProvider : KoinComponent {
    DISCORD,
    GOOGLE;

    private val dotenv by inject<Dotenv>()
    private val httpClient by inject<HttpClient>()

    val userInfo: suspend (token: String) -> OAuthUserInfo
        get() = when (this) {
            DISCORD -> { token ->
                val raw = httpClient.get("https://discord.com/api/users/@me") {
                    headers { append(HttpHeaders.Authorization, "Bearer $token") }
                }.body<DiscordRaw>()
                OAuthUserInfo(
                    id = raw.id,
                    email = raw.email,
                    username = raw.username
                )
            }

            GOOGLE -> { token ->
                val raw = httpClient.get("https://openidconnect.googleapis.com/v1/userinfo") {
                    headers { append(HttpHeaders.Authorization, "Bearer $token") }
                }.body<GoogleRaw>()
                OAuthUserInfo(
                    id = raw.sub,
                    email = raw.email,
                    username = raw.name
                )
            }
        }

    val settings: OAuthServerSettings.OAuth2ServerSettings
        get() = when (this) {
            DISCORD -> OAuthServerSettings.OAuth2ServerSettings(
                name = "discord",
                authorizeUrl = "https://discord.com/api/oauth2/authorize",
                accessTokenUrl = "https://discord.com/api/oauth2/token",
                requestMethod = HttpMethod.Post,
                clientId = dotenv["DISCORD_CLIENT_ID"],
                clientSecret = dotenv["DISCORD_CLIENT_SECRET"],
                defaultScopes = listOf("email", "identify"),
                onStateCreated = { call, state ->
                    call.request.queryParameters["redirectUrl"]?.let {
                        redirects[state] = it
                    }
                }
            )

            GOOGLE -> OAuthServerSettings.OAuth2ServerSettings(
                name = "google",
                authorizeUrl = "https://accounts.google.com/o/oauth2/auth",
                accessTokenUrl = "https://oauth2.googleapis.com/token",
                requestMethod = HttpMethod.Post,
                clientId = dotenv["GOOGLE_CLIENT_ID"],
                clientSecret = dotenv["GOOGLE_CLIENT_SECRET"],
                defaultScopes = listOf(
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email"
                ),
                extraAuthParameters = listOf("access_type" to "offline"),
                onStateCreated = { call, state ->
                    call.request.queryParameters["redirectUrl"]?.let {
                        redirects[state] = it
                    }
                }
            )
        }

    @Serializable
    private data class DiscordRaw(
        val id: String,
        val email: String,
        val username: String
    )

    @Serializable
    private data class GoogleRaw(
        val sub: String,
        val email: String,
        val name: String
    )
}