package dev.kamiql.domain.auth

import dev.kamiql.domain.user.Account
import kotlinx.serialization.Serializable

@Serializable
data class Credentials(
    val passwordHash: String,
    val accounts: MutableMap<OAuthProvider, Account>
)