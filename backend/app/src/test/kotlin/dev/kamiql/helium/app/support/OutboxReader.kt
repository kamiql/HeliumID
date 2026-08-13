package dev.kamiql.helium.app.support

import dev.kamiql.helium.app.HeliumComponents
import dev.kamiql.helium.domain.event.VerificationPurpose
import dev.kamiql.helium.persistence.OutboxEventsTable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import kotlin.test.fail

/**
 * Reads what the flows published to the transactional outbox.
 *
 * ### Why tests read the outbox rather than a mailbox
 *
 * Email verification and password reset both hand the user a secret that only ever exists in
 * transit — [dev.kamiql.helium.identity.VerificationTokenService] stores a hash and puts the
 * plaintext in an outbox payload for the mailer to render into a link. An end-to-end test has
 * the same problem a user does: it has to get the token out of the message. Reading the outbox
 * row is the shortest honest path. Standing up an SMTP sink would test the mailer, which has its
 * own tests, and would put a second process between a flow and the assertion about it.
 *
 * ### What this proves in passing
 *
 * CLAUDE.md requires that notification work be a transactional outbox effect and never an inline
 * side effect. Every test that recovers a token this way depends on the row being there — and on
 * it being *absent* when the surrounding transaction rolled back. So the harness does not merely
 * tolerate the outbox; it makes the invariant load-bearing.
 *
 * Rows are read, never consumed: the dispatcher is not running in tests, so `processed_at` stays
 * null and nothing here competes with it.
 */
class OutboxReader(private val components: HeliumComponents) {

    /** One published event, with its payload already parsed. */
    data class Entry(val type: String, val payload: JsonObject) {

        /** A payload field, or `null` when the event does not carry it. */
        operator fun get(field: String): String? = (payload[field] as? JsonPrimitive)?.content

        fun require(field: String): String =
            get(field) ?: fail("outbox event '$type' has no '$field' field; payload was $payload")
    }

    /** Every event published so far, oldest first. */
    suspend fun all(): List<Entry> = withContext(Dispatchers.IO) {
        suspendTransaction(db = components.database.database) {
            OutboxEventsTable.selectAll()
                .orderBy(OutboxEventsTable.createdAt)
                .map { row ->
                    Entry(
                        type = row[OutboxEventsTable.eventType],
                        payload = JSON.parseToJsonElement(row[OutboxEventsTable.payload]) as JsonObject,
                    )
                }
        }
    }

    suspend fun ofType(type: String): List<Entry> = all().filter { it.type == type }

    /**
     * The most recent event of [type].
     *
     * Most recent rather than only: issuing a new verification token invalidates the previous
     * one, so after a resend the earlier row is a token that no longer works. A test asserting
     * on "the" token means the current one.
     */
    suspend fun latest(type: String): Entry =
        ofType(type).lastOrNull() ?: fail(
            "no '$type' event in the outbox; published so far: " +
                all().map { it.type }.ifEmpty { listOf("nothing") },
        )

    /**
     * The plaintext email-verification token.
     *
     * [purpose] separates initial verification from an email change: both publish the same event
     * type and only the field tells them apart, so a test confirming an address change would
     * otherwise happily redeem the signup token and pass for the wrong reason.
     */
    suspend fun emailVerificationToken(
        purpose: VerificationPurpose = VerificationPurpose.EMAIL_VERIFICATION,
    ): String =
        ofType("user.email-verification-requested")
            .lastOrNull { it["purpose"] == purpose.token }
            ?.require("token_id")
            ?: fail(
                "no email-verification event with purpose '${purpose.token}'; saw " +
                    ofType("user.email-verification-requested").map { it["purpose"] },
            )

    suspend fun passwordResetToken(): String =
        latest("user.password-reset-requested").require("token_id")

    /** Asserts nothing of [type] was published — the negative half of an outbox assertion. */
    suspend fun assertNone(type: String) {
        val found = ofType(type)
        if (found.isNotEmpty()) {
            fail("expected no '$type' event, found ${found.size}: ${found.map { it.payload }}")
        }
    }

    private companion object {
        val JSON = Json { ignoreUnknownKeys = true }
    }
}
