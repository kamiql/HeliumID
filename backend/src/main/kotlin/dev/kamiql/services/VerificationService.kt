package dev.kamiql.services

import dev.kamiql.domain.user.User
import dev.kamiql.storage.UserRepository
import io.ktor.http.*
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

@Serializable
enum class VerificationType : KoinComponent {
    EMAIL {
        private val codes = ConcurrentHashMap<UUID, String>()

        override suspend fun create(
            user: User,
            id: UUID
        ) {
            val code = generateCode()

            codes[id] = code

            mailService.send(
                user = user,
                subject = "Confirm action",
                template = "confirm-action",
                variables = mapOf(
                    "code" to code
                )
            )
        }

        override suspend fun verify(
            user: User,
            id: UUID,
            code: String
        ): Boolean {
            return codes.remove(id) == code
        }

        override fun cleanup(id: UUID) {
            codes.remove(id)
        }
    },
    TOTP {
        override suspend fun create(
            user: User,
            id: UUID
        ) {}

        override suspend fun verify(
            user: User,
            id: UUID,
            code: String
        ): Boolean {
            if (!user.totpEnabled) return false
            val totpSecret = user.credentials().totpSecret ?: return false
            return TotpService.verify(totpSecret, code)
        }

        override fun cleanup(id: UUID) {}
    };

    val mailService: MailService by inject()

    abstract suspend fun create(
        user: User,
        id: UUID
    )

    abstract suspend fun verify(
        user: User,
        id: UUID,
        code: String
    ): Boolean

    abstract fun cleanup(id: UUID)

    companion object {
        private val random = SecureRandom()

        private fun generateCode(): String {
            return random.nextInt(100000, 1000000).toString()
        }
    }
}

object VerificationManager {

    private val verifications = ConcurrentHashMap<UUID, Verification>()

    suspend fun create(
        user: User,
        type: VerificationType,
        callback: suspend (ApplicationCall) -> Unit
    ): UUID {
        val id = UUID.randomUUID()

        verifications[id] = Verification(
            id = id,
            user = user,
            type = type,
            expiresAt = Clock.System.now() + 5.minutes,
            callback = callback
        )

        type.create(
            user = user,
            id = id
        )

        return id
    }

    suspend fun confirm(
        call: ApplicationCall,
        id: UUID,
        code: String
    ): Boolean {
        val verification = verifications[id]
            ?: return false

        if (verification.expiresAt <= Clock.System.now()) {
            verifications.remove(id)
            verification.type.cleanup(id)
            return false
        }

        if (!verification.type.verify(
                user = verification.user,
                id = id,
                code = code
            )
        ) {
            return false
        }

        verifications.remove(id)
        verification.callback(call)

        return true
    }

    private data class Verification(
        val id: UUID,
        val user: User,
        val type: VerificationType,
        val expiresAt: Instant,
        val callback: suspend (ApplicationCall) -> Unit
    )
}

suspend fun RoutingContext.verify(
    type: VerificationType,
    userId: UUID,
    callback: suspend (ApplicationCall) -> Unit
) {
    val user = UserRepository[userId]
        ?: return call.respond(HttpStatusCode.NotFound)

    val id = VerificationManager.create(
        user = user,
        type = type,
        callback = callback
    )

    call.respond(HttpStatusCode.Accepted, id)
}