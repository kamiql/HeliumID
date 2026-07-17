package dev.kamiql.domain.api.auth

import dev.kamiql.domain.user.Email
import kotlinx.serialization.Serializable

@Serializable
data class CreateUserRequest(
    val username: String,
    val firstName: String,
    val lastName: String,
    val email: Email,
    val password: String
)