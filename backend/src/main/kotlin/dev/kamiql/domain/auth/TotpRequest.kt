package dev.kamiql.domain.auth

import kotlinx.serialization.Serializable

@Serializable
data class TotpRequest(
    val code: String
)