package dev.kamiql.storage

import dev.kamiql.database.MongoRepository
import dev.kamiql.domain.auth.Credentials
import dev.kamiql.domain.auth.OAuthProvider
import java.util.*

object CredentialRepository : MongoRepository<UUID, Credentials>("credentials", Credentials.serializer()) {
    suspend fun findUserByOAuth(
        provider: OAuthProvider,
        id: String
    ): UUID? {
        return findAll()
            .entries
            .firstOrNull { (_, credentials) ->
                credentials.accounts.values.any { it.provider == provider && it.id == id }
            }
            ?.key
    }
}