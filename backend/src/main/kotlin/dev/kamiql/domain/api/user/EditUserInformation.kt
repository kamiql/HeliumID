package dev.kamiql.domain.api.user

import kotlinx.serialization.Serializable

@Serializable
data class EditUserInformation(
    val username: String? = null,
    val firstName: String? = null,
    val lastName: String? = null,
    val email: String? = null,
)
