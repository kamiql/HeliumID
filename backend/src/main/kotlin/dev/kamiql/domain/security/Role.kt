package dev.kamiql.domain.security

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class Role(
    val id: @Contextual UUID,
    val name: String,
    val color: String,
    val permissions: MutableSet<Permission>,
    val inherits: MutableSet<@Contextual UUID> = mutableSetOf()
)
