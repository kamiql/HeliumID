package dev.kamiql.domain.user

import kotlinx.serialization.Serializable

@Serializable
@JvmInline
value class Email(
    val value: String
) {
    override fun toString() = value
}