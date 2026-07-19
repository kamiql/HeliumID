package dev.kamiql.domain.api.auth

import dev.kamiql.services.VerificationType
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class MFARequest(
    val userId: @Contextual UUID,
    val type: VerificationType,
)