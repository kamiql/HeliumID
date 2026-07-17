package dev.kamiql.domain.session

import dev.kamiql.services.VerificationType
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class VerificationSession(
    val id: @Contextual UUID,
    val type: VerificationType
)