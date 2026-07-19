package dev.kamiql.domain.user

import dev.kamiql.domain.auth.Credentials
import dev.kamiql.domain.auth.OAuthProvider
import dev.kamiql.domain.security.Role
import dev.kamiql.services.VerificationType
import dev.kamiql.storage.CredentialRepository
import dev.kamiql.storage.RoleRepository
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
    val totpEnabled: Boolean = false,

    val linkedAccounts: MutableMap<OAuthProvider, Account> = mutableMapOf(),

    val roles: MutableSet<@Contextual UUID> = mutableSetOf(),

    val createdAt: Instant = Clock.System.now()
) {
    suspend fun credentials(): Credentials = CredentialRepository[id]!!
    suspend fun roles(): Set<Role> = roles.mapNotNull { RoleRepository[it] }.toSet()

    fun requireMFA(): Boolean = emailVerified || totpEnabled
    fun mfaMethods(): List<VerificationType> {
        val types = mutableListOf<VerificationType>()

        if (emailVerified) types.add(VerificationType.EMAIL)
        if (totpEnabled) types.add(VerificationType.TOTP)

        return types
    }
}