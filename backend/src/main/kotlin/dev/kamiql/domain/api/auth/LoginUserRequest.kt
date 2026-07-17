package dev.kamiql.domain.api.auth

import kotlinx.serialization.Serializable

@Serializable
data class LoginUserRequest(
    val email: String,
    val password: String
)