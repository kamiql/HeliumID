package dev.kamiql.domain.auth

import kotlinx.serialization.Serializable

@Serializable
data class Credentials(
    val passwordHash: String,
    val accounts: MutableMap<OAuthProvider, OAuthData>
)