package dev.kamiql.domain.api.auth

import kotlinx.serialization.Serializable

@Serializable
data class ResetPasswordRequest(
    val old: String,
    val new: String
)