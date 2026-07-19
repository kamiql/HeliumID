package dev.kamiql.serializer.session

import dev.kamiql.domain.session.MFASession
import io.ktor.server.sessions.SessionSerializer
import kotlinx.serialization.json.Json
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

object MFASessionSerializer : SessionSerializer<MFASession>, KoinComponent {
    val json: Json by inject()

    override fun serialize(session: MFASession): String {
        return json.encodeToString(MFASession.serializer(), session)
    }

    override fun deserialize(text: String): MFASession {
        return json.decodeFromString(MFASession.serializer(), text)
    }
}