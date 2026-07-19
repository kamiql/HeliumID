package dev.kamiql.domain.session

import dev.kamiql.services.VerificationType
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class MFASession(
    val userId: @Contextual UUID,
    val id: @Contextual UUID,
    val type: VerificationType
)