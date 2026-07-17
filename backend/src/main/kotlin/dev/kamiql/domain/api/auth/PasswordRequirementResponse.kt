package dev.kamiql.domain.api.auth

import kotlinx.serialization.Serializable

@Serializable
data class PasswordRequirementResponse(
    val regex: String,
    val description: String
)
