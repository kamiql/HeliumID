package dev.kamiql.domain.auth

import kotlinx.serialization.Serializable

@Serializable
data class OAuthData(
    val provider: OAuthProvider,
    val id: String,
    val accessToken: String,
    val refreshToken: String? = null
)