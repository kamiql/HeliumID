package dev.kamiql.helium.audit

import dev.kamiql.helium.flow.port.AuditEntry
import dev.kamiql.helium.flow.port.AuditPort

/**
 * What is allowed to reach `audit_logs.metadata_json`.
 *
 * The audit trail is not a debug log. It is queried by operators, exported to a SIEM, and it
 * outlives the rows it describes — whatever lands in it is retained for as long as the trail is,
 * and there is no flow that goes back and removes it.
 *
 * The metadata a flow emits is assembled from its own state (`FlowState.diagnosticSnapshot`), so
 * the primary control is marking a `FlowStateKey` sensitive at the point it is written. That
 * control is a per-call-site decision by whoever adds the step, which is exactly the kind of
 * decision that is eventually forgotten. WebAuthn makes the consequence concrete: credential ids,
 * COSE public keys, challenges, client-data JSON, authenticator data and signatures all pass
 * through flow state as ordinary strings, and none of them belong in a permanent table.
 *
 * This is the backstop for that: a denylist on key names plus a hard cap on value length, applied
 * centrally. It is defence in depth, not a licence to stop marking keys sensitive.
 */
object AuditMetadataPolicy {

    /** Replacement written in place of a rejected value, so the omission itself is auditable. */
    const val REDACTED: String = "[redacted]"

    /**
     * Longest value retained.
     *
     * Every field that legitimately belongs here is a short identifier, enum name or count. A
     * long value is either a blob that should not be stored or a payload echoed by mistake, and
     * both are better truncated to a marker than kept.
     */
    const val MAX_VALUE_LENGTH: Int = 256

    /**
     * Keys the flow engine itself writes, exempt from [FORBIDDEN_KEY_FRAGMENTS].
     *
     * `challenge` is the reason this list exists: the engine stores the *challenge code* under
     * that name (`mfa_required`, `consent_required`), which is a closed vocabulary and safe. A
     * key like `webauthn_challenge` is not an exact match and is still redacted.
     */
    val ALWAYS_ALLOWED_KEYS: Set<String> = setOf("requirement", "challenge", "error", "events")

    /**
     * Substrings that mark a key as carrying material that must never be retained.
     *
     * Matched case-insensitively against the whole key, so `webauthn_public_key`, `publicKey` and
     * `cred_id` are all caught. Deliberately broad: a false positive costs one diagnostic field,
     * a false negative costs a permanent record of authenticator material.
     */
    val FORBIDDEN_KEY_FRAGMENTS: List<String> = listOf(
        // WebAuthn
        "credential", "cred_id", "publickey", "public_key", "challenge", "signature",
        "attestation", "assertion", "authenticator_data", "authenticatordata",
        "client_data", "clientdata",
        // everything else that is a credential or bearer of one
        "secret", "token", "password", "passphrase", "cookie", "otp", "code", "recovery",
    )

    /**
     * Applies the policy.
     *
     * Keys are kept — an operator seeing `credential_id: [redacted]` learns that the field was
     * present and suppressed, whereas a dropped key is indistinguishable from a step that never
     * ran.
     */
    fun scrub(metadata: Map<String, String>): Map<String, String> =
        metadata.mapValues { (key, value) ->
            when {
                key in ALWAYS_ALLOWED_KEYS -> value.takeIf { it.length <= MAX_VALUE_LENGTH } ?: REDACTED
                isForbidden(key) -> REDACTED
                value.length > MAX_VALUE_LENGTH -> REDACTED
                else -> value
            }
        }

    fun isForbidden(key: String): Boolean {
        if (key in ALWAYS_ALLOWED_KEYS) return false
        val normalized = key.lowercase()
        return FORBIDDEN_KEY_FRAGMENTS.any { it in normalized }
    }
}

/**
 * Wraps the real [AuditPort] and applies [AuditMetadataPolicy] on the way through.
 *
 * Composition rather than a change to the writer, so the rule holds for every `AuditPort`
 * implementation — including the ones used in tests, which is where an accidental leak is most
 * likely to be written and least likely to be noticed.
 */
class ScrubbedAuditPort(private val delegate: AuditPort) : AuditPort {

    override suspend fun record(entry: AuditEntry) {
        delegate.record(entry.copy(metadata = AuditMetadataPolicy.scrub(entry.metadata)))
    }
}
