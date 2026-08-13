package dev.kamiql.helium.audit

import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.flow.port.AuditEntry
import dev.kamiql.helium.flow.port.AuditOutcome
import dev.kamiql.helium.flow.port.AuditPort
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuditMetadataPolicyTest {

    @Test
    fun `webauthn material never survives into metadata`() {
        val scrubbed = AuditMetadataPolicy.scrub(
            mapOf(
                "credential_id" to "AQIDBAUGBwgJCgsMDQ4PEA",
                "credentialId" to "AQIDBAUGBwgJCgsMDQ4PEA",
                "cred_id" to "AQIDBAUGBwgJCgsMDQ4PEA",
                "public_key" to "pQECAyYgASFYIA",
                "publicKey" to "pQECAyYgASFYIA",
                "webauthn_challenge" to "Zm9vYmFyYmF6",
                "signature" to "MEUCIQD",
                "attestation_object" to "o2NmbXRk",
                "authenticator_data" to "SZYN5YgOjGh0NB",
                "client_data_json" to "eyJ0eXBlIjoid2ViY",
                "assertion" to "…",
            ),
        )

        scrubbed.forEach { (key, value) ->
            assertEquals(AuditMetadataPolicy.REDACTED, value, "$key leaked into the audit trail")
        }
    }

    @Test
    fun `other credential-bearing keys are redacted too`() {
        val scrubbed = AuditMetadataPolicy.scrub(
            mapOf(
                "totp_secret" to "JBSWY3DP",
                "refresh_token" to "opaque",
                "password" to "hunter2",
                "session_cookie" to "abc",
                "recovery_code" to "1234-5678",
                "authorization_code" to "xyz",
            ),
        )

        scrubbed.values.forEach { assertEquals(AuditMetadataPolicy.REDACTED, it) }
    }

    @Test
    fun `the engine's own metadata keys survive`() {
        val metadata = mapOf(
            "requirement" to "has-permission:admin.users.read",
            "challenge" to "mfa_required",
            "error" to "invalid_credentials",
            "events" to "MfaEnrolled,SessionRevoked",
            "method" to "webauthn",
            "factor_count" to "2",
        )

        assertEquals(metadata, AuditMetadataPolicy.scrub(metadata))
    }

    @Test
    fun `an oversized value is redacted whatever it is called`() {
        val scrubbed = AuditMetadataPolicy.scrub(
            mapOf("harmless_looking" to "x".repeat(AuditMetadataPolicy.MAX_VALUE_LENGTH + 1)),
        )

        assertEquals(AuditMetadataPolicy.REDACTED, scrubbed.getValue("harmless_looking"))
    }

    @Test
    fun `redaction keeps the key so the omission is visible`() {
        val scrubbed = AuditMetadataPolicy.scrub(mapOf("credential_id" to "AQID"))

        assertTrue("credential_id" in scrubbed)
        assertNotNull(scrubbed["credential_id"])
    }

    @Test
    fun `the port decorator applies the policy and forwards everything else`() = runTest {
        val recorded = mutableListOf<AuditEntry>()
        val delegate = object : AuditPort {
            override suspend fun record(entry: AuditEntry) {
                recorded += entry
            }
        }
        val entry = AuditEntry(
            eventType = AuditEventType.WEBAUTHN_ENROLLED,
            outcome = AuditOutcome.SUCCESS,
            actorUserId = null,
            subjectUserId = null,
            clientId = null,
            requestId = RequestId("req-1"),
            ipHash = "hash",
            userAgentHash = "hash",
            occurredAt = Instant.EPOCH,
            metadata = mapOf("credential_id" to "AQID", "factor_count" to "2"),
        )

        ScrubbedAuditPort(delegate).record(entry)

        val written = recorded.single()
        assertEquals(AuditEventType.WEBAUTHN_ENROLLED, written.eventType)
        assertEquals(RequestId("req-1"), written.requestId)
        assertEquals(AuditMetadataPolicy.REDACTED, written.metadata.getValue("credential_id"))
        assertEquals("2", written.metadata.getValue("factor_count"))
    }
}
