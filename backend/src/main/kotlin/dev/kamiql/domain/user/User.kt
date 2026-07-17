package dev.kamiql.domain.user

import dev.kamiql.domain.auth.Credentials
import dev.kamiql.domain.auth.OAuthProvider
import dev.kamiql.storage.CredentialRepository
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import java.util.*
import kotlin.time.Clock
import kotlin.time.Instant

@Serializable
data class User(
    val id: @Contextual UUID,

    var username: String,
    var username_lower: String,

    val firstName: String,
    val lastName: String,

    val email: Email,

    val emailVerified: Boolean = false,

    val linkedAccounts: MutableSet<OAuthProvider> = mutableSetOf(),

    val createdAt: Instant = Clock.System.now()
) {
    suspend fun credentials(): Credentials = CredentialRepository[id]!!
}