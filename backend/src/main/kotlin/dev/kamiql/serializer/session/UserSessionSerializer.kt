package dev.kamiql.serializer.session

import dev.kamiql.domain.session.UserSession
import io.ktor.server.sessions.*
import kotlinx.serialization.json.Json
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

object UserSessionSerializer : SessionSerializer<UserSession>, KoinComponent {
    val json: Json by inject()

    override fun serialize(session: UserSession): String {
        return json.encodeToString(UserSession.serializer(), session)
    }

    override fun deserialize(text: String): UserSession {
        return json.decodeFromString(UserSession.serializer(), text)
    }
}