package dev.kamiql.services

import dev.kamiql.domain.session.UserSession
import dev.kamiql.domain.user.User
import dev.kamiql.storage.UserRepository
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

enum class VerificationType : KoinComponent {
    EMAIL {
        override suspend fun create(
            user: User,
            id: UUID
        ) {
            val secret = generateSecret()

            secrets[id] = secret

            mailService.send(
                user = user,
                subject = "Confirm action",
                template = "confirm-action",
                variables = mapOf(
                    "secret" to secret,
                    "id" to id
                )
            )
        }

        override suspend fun verify(
            id: UUID,
            secret: String
        ): Boolean {
            return secrets.remove(id) == secret
        }

        override fun cleanup(id: UUID) {
            secrets.remove(id)
        }
    };

    val mailService: MailService by inject()

    abstract suspend fun create(
        user: User,
        id: UUID
    )

    abstract suspend fun verify(
        id: UUID,
        secret: String
    ): Boolean

    abstract fun cleanup(id: UUID)

    companion object {
        private val random = SecureRandom()
        private val secrets = ConcurrentHashMap<UUID, String>()

        private fun generateSecret(): String {
            val bytes = ByteArray(32)

            random.nextBytes(bytes)

            return bytes.joinToString("") {
                "%02x".format(it)
            }
        }
    }
}

enum class VerificationStatus {
    PENDING,
    COMPLETED,
    EXPIRED,
    NOT_FOUND
}

object VerificationManager {

    private val verifications = ConcurrentHashMap<UUID, Verification>()
    private val completed = ConcurrentHashMap.newKeySet<UUID>()

    suspend fun create(
        user: User,
        type: VerificationType,
        callback: suspend () -> Unit
    ): UUID {
        val id = UUID.randomUUID()

        val verification = Verification(
            id = id,
            type = type,
            expiresAt = Clock.System.now() + 5.minutes,
            callback = callback
        )

        verifications[id] = verification

        type.create(
            user = user,
            id = id
        )

        return id
    }

    suspend fun confirm(
        id: UUID,
        type: VerificationType,
        secret: String
    ): Boolean {
        val verification = verifications[id]
            ?: return false

        if (verification.type != type) {
            return false
        }

        if (verification.expiresAt <= Clock.System.now()) {
            verifications.remove(id)
            verification.type.cleanup(id)

            return false
        }

        if (!verification.type.verify(id, secret)) {
            return false
        }

        verifications.remove(id)
        completed.add(id)

        verification.callback()

        return true
    }

    fun status(id: UUID): VerificationStatus {
        if (completed.contains(id)) {
            return VerificationStatus.COMPLETED
        }

        val verification = verifications[id]
            ?: return VerificationStatus.NOT_FOUND

        if (verification.expiresAt <= Clock.System.now()) {
            verifications.remove(id)
            verification.type.cleanup(id)

            return VerificationStatus.EXPIRED
        }

        return VerificationStatus.PENDING
    }

    private data class Verification(
        val id: UUID,
        val type: VerificationType,
        val expiresAt: Instant,
        val callback: suspend () -> Unit
    )
}

suspend fun RoutingContext.verify(
    type: VerificationType,
    callback: suspend () -> Unit
) {
    val session = call.sessions.get<UserSession>()
        ?: return call.respond(HttpStatusCode.Unauthorized)

    val user = UserRepository[session.userId]
        ?: return call.respond(HttpStatusCode.NotFound)

    val id = VerificationManager.create(
        user = user,
        type = type,
        callback = callback
    )

    call.respond(HttpStatusCode.Accepted, id)
}