package dev.kamiql.domain.session

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class UserSession(
    val id: @Contextual UUID,
    val userId: @Contextual UUID
)