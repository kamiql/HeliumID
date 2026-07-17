package dev.kamiql.storage

import dev.kamiql.database.MongoRepository
import io.ktor.server.sessions.*
import kotlinx.serialization.Serializable

object CookieSessionRepository : SessionStorage, MongoRepository<String, CookieSessionRepository.Session>("user_session", Session.serializer()) {
    @Serializable
    data class Session(
        val id: String,
    )

    override suspend fun write(id: String, value: String) {
        this[id] = Session(value)
    }

    override suspend fun invalidate(id: String) {
        this.delete(id)
    }

    override suspend fun read(id: String): String {
        return this[id]?.id ?: throw NoSuchElementException("Session $id not found")
    }
}