package dev.kamiql.domain.user

import kotlinx.serialization.Serializable

@Serializable
data class Account(
    val id: String,
    val email: String,
    val username: String
)