package dev.kamiql.domain.api.auth

import dev.kamiql.services.VerificationType
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class RequireMFAResponse(
    val userId: @Contextual UUID,
    val types: List<VerificationType>
)