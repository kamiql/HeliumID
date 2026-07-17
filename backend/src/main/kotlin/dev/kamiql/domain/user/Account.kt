package dev.kamiql.domain.user

import dev.kamiql.domain.auth.OAuthProvider
import kotlinx.serialization.Serializable

@Serializable
data class Account(
    val provider: OAuthProvider,
    val id: String,
    val email: String,
    val username: String,
    val accessToken: String,
    val refreshToken: String? = null
)