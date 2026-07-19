package dev.kamiql.storage

import dev.kamiql.domain.auth.Credentials
import dev.kamiql.domain.security.Permission
import dev.kamiql.domain.security.Role
import dev.kamiql.domain.user.Email
import dev.kamiql.domain.user.User
import dev.kamiql.services.BCryptService
import io.github.cdimascio.dotenv.Dotenv
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.util.UUID

object DefaultDataSeeder : KoinComponent {
    val dotenv: Dotenv by inject()

    suspend fun seed() {
        val role = RoleRepository.findAll()
            .values
            .firstOrNull { it.name == "Administrator" }
            ?: Role(
                id = UUID.randomUUID(),
                name = "Administrator",
                color = "#ed4245",
                permissions = mutableSetOf(Permission.ADMINISTRATOR)
            ).also {
                RoleRepository[it.id] = it
            }

        val username = dotenv["DEFAULT_ADMIN_USERNAME"]
        val firstName = dotenv["DEFAULT_ADMIN_FIRST_NAME"]
        val lastName = dotenv["DEFAULT_ADMIN_LAST_NAME"]
        val email = dotenv["DEFAULT_ADMIN_EMAIL"]
        val password = dotenv["DEFAULT_ADMIN_PASSWORD"]

        require(!username.isNullOrBlank())
        require(!firstName.isNullOrBlank())
        require(!lastName.isNullOrBlank())
        require(!email.isNullOrBlank())
        require(!password.isNullOrBlank())

        val user = UserRepository.findBy(
            "username_lower",
            username.lowercase()
        ) ?: User(
            id = UUID.randomUUID(),
            username = username,
            username_lower = username.lowercase(),
            firstName = firstName,
            lastName = lastName,
            email = Email(email),
            emailVerified = true,
            roles = mutableSetOf(role.id)
        ).also {
            UserRepository[it.id] = it
        }

        if (!user.roles.contains(role.id)) {
            user.roles.add(role.id)
            UserRepository[user.id] = user
        }

        if (CredentialRepository[user.id] == null) {
            CredentialRepository[user.id] = Credentials(
                passwordHash = BCryptService.hash(password),
                accounts = mutableMapOf()
            )
        }
    }
}