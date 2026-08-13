package dev.kamiql.helium.audit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Guards the severity classification.
 *
 * The regression these cover is not a crash: it is an alert that quietly stops firing because a
 * new second factor's removal event was never added to the set.
 */
class SecurityEventsTest {

    @Test
    fun `removing any second factor is high severity`() {
        AuditEventType.SECOND_FACTOR_REMOVED.forEach { event ->
            assertTrue(AuditEventType.isHighSeverity(event), "$event must page")
            assertTrue(event in AuditEventType.HIGH_SEVERITY, "$event must be listed explicitly")
        }
    }

    @Test
    fun `totp and webauthn removal are both classified`() {
        assertTrue(AuditEventType.isHighSeverity(AuditEventType.TOTP_DISABLED))
        assertTrue(AuditEventType.isHighSeverity(AuditEventType.WEBAUTHN_REMOVED))
    }

    @Test
    fun `a removal event nobody remembered to list is still high severity`() {
        // The exact bug this rule exists for: a future factor ships with its own flow id and the
        // constant above is not updated.
        assertTrue(AuditEventType.isHighSeverity("account.mfa.passkey.remove"))
        assertTrue(AuditEventType.isHighSeverity("account.mfa.sms.disable"))
        assertTrue(AuditEventType.isHighSeverity("account.mfa.hardware-key.revoke"))
    }

    @Test
    fun `enrolment and routine events are not high severity`() {
        assertFalse(AuditEventType.isHighSeverity(AuditEventType.TOTP_ENROLLED))
        assertFalse(AuditEventType.isHighSeverity(AuditEventType.WEBAUTHN_ENROLLED))
        assertFalse(AuditEventType.isHighSeverity(AuditEventType.WEBAUTHN_ENROLLMENT_STARTED))
        assertFalse(AuditEventType.isHighSeverity(AuditEventType.LOGIN_SUCCEEDED))
        assertFalse(AuditEventType.isHighSeverity(AuditEventType.RECOVERY_CODES_REGENERATED))
    }

    @Test
    fun `the structural rule does not reach outside mfa management`() {
        assertFalse(AuditEventType.isHighSeverity("account.provider.unlink"))
        assertFalse(AuditEventType.isHighSeverity("identity.revoke-session"))
        assertFalse(AuditEventType.isHighSeverity("admin.user.revoke-sessions"))
    }

    @Test
    fun `mfa event constants agree with the flow ids that produce them`() {
        // These strings are what FlowRunner writes into event_type. If a flow id changes, the
        // constant is dead and every query keyed on it returns nothing.
        assertEquals("account.mfa.totp.confirm", AuditEventType.TOTP_ENROLLED)
        assertEquals("account.mfa.totp.disable", AuditEventType.TOTP_DISABLED)
        assertEquals("account.mfa.webauthn.begin", AuditEventType.WEBAUTHN_ENROLLMENT_STARTED)
        assertEquals("account.mfa.webauthn.confirm", AuditEventType.WEBAUTHN_ENROLLED)
        assertEquals("account.mfa.webauthn.remove", AuditEventType.WEBAUTHN_REMOVED)
    }
}
