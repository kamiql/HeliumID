package dev.kamiql.helium.audit

/**
 * The catalogue of audit event types.
 *
 * Constants rather than free strings, because these values are queried by operators and
 * alerted on. A typo in a literal produces an event nobody is watching for, which is worse
 * than no event at all.
 */
object AuditEventType {

    // authentication
    const val LOGIN_SUCCEEDED = "auth.login-succeeded"
    const val LOGIN_FAILED = "auth.login-failed"
    const val MFA_COMPLETED = "auth.mfa-completed"
    const val MFA_FAILED = "auth.mfa-failed"
    const val LOGOUT = "auth.logout"
    const val SESSION_REVOKED = "auth.session-revoked"

    // account lifecycle
    const val REGISTERED = "identity.register"
    const val EMAIL_VERIFIED = "identity.verify-email"
    const val PASSWORD_CHANGED = "account.change-password"
    const val PASSWORD_RESET_REQUESTED = "identity.password-reset.request"
    const val PASSWORD_RESET_COMPLETED = "identity.password-reset.complete"
    const val EMAIL_CHANGED = "account.email-change.confirm"
    const val ACCOUNT_DELETED = "account.delete"

    // MFA
    //
    // These values are flow ids: `FlowRunner` writes `flow.auditEventType` into `event_type`, and
    // that defaults to the flow's id. There is therefore one constant per *factor type*, not one
    // per concept. A single `MFA_DISABLED` naming only the TOTP flow is not a shorthand — it is a
    // filter that silently excludes every other factor, and anything keyed on it (alerting,
    // [HIGH_SEVERITY], operator queries) stops covering that factor the moment it ships.
    const val TOTP_ENROLLED = "account.mfa.totp.confirm"
    const val TOTP_DISABLED = "account.mfa.totp.disable"
    const val WEBAUTHN_ENROLLMENT_STARTED = "account.mfa.webauthn.begin"
    const val WEBAUTHN_ENROLLED = "account.mfa.webauthn.confirm"
    const val WEBAUTHN_REMOVED = "account.mfa.webauthn.remove"
    const val RECOVERY_CODES_REGENERATED = "account.mfa.recovery-codes.regenerate"

    /** Every event that adds a second factor. One entry per factor type. */
    val SECOND_FACTOR_ENROLLED: Set<String> = setOf(TOTP_ENROLLED, WEBAUTHN_ENROLLED)

    /**
     * Every event that takes a second factor away. All of these are [HIGH_SEVERITY].
     *
     * Removing a factor is the single most valuable action available to somebody holding a stolen
     * session: it converts temporary access into durable access. Grouping the events means the
     * severity decision is made once for the category rather than re-argued per factor.
     */
    val SECOND_FACTOR_REMOVED: Set<String> = setOf(TOTP_DISABLED, WEBAUTHN_REMOVED)

    // identities
    const val PROVIDER_LINKED = "identity.provider-linked"
    const val PROVIDER_UNLINKED = "account.provider.unlink"

    // protocol
    const val AUTHORIZE = "oauth.authorize"
    const val TOKEN_ISSUED = "oauth.token"
    const val TOKEN_REVOKED = "oauth.revoke"
    const val REFRESH_REUSE_DETECTED = "token.refresh-reuse-detected"

    // trusted devices
    const val TRUSTED_DEVICE_ADDED = "auth.trusted-device-added"
    const val TRUSTED_DEVICE_USED = "auth.trusted-device-used"
    const val TRUSTED_DEVICE_REVOKED = "auth.trusted-device-revoked"
    const val TRUSTED_DEVICE_REUSE_DETECTED = "auth.trusted-device-reuse-detected"

    // administration
    const val ADMIN_USER_STATUS_CHANGED = "admin.user.status"
    const val ADMIN_ROLES_ASSIGNED = "admin.user.roles"
    const val ADMIN_SESSIONS_REVOKED = "admin.user.revoke-sessions"
    const val CLIENT_REGISTERED = "admin.client.register"
    const val CLIENT_SECRET_ROTATED = "admin.client.rotate-secret"

    /**
     * Events that should page somebody, or at least raise a ticket.
     *
     * Refresh-token reuse is the clearest signal of credential theft this system can produce;
     * the rest indicate an account takeover in progress or an administrative action worth a
     * second pair of eyes.
     *
     * Classify with [isHighSeverity] rather than testing membership directly — see the note
     * there on why an explicit set is not sufficient on its own.
     */
    val HIGH_SEVERITY: Set<String> = setOf(
        REFRESH_REUSE_DETECTED,
        // A device cookie can only reappear after rotation if it was copied off the machine.
        // Lower impact than a stolen refresh token — it is useless without the password — but
        // the same category of evidence, so it gets the same attention.
        TRUSTED_DEVICE_REUSE_DETECTED,
        ADMIN_USER_STATUS_CHANGED,
        ADMIN_ROLES_ASSIGNED,
        CLIENT_SECRET_ROTATED,
    ) + SECOND_FACTOR_REMOVED

    /** Prefix shared by every self-service MFA management flow id. */
    private const val MFA_EVENT_PREFIX = "account.mfa."

    /** Trailing flow-id segments that mean "a factor was taken away". */
    private val FACTOR_REMOVAL_VERBS = setOf("disable", "remove", "delete", "revoke", "unenroll")

    /**
     * Whether [eventType] warrants a page.
     *
     * Use this instead of `eventType in HIGH_SEVERITY`. A hand-maintained set only contains what
     * somebody remembered to add, and the failure mode of forgetting is *silence*: the alert
     * simply never fires, and nothing else looks wrong. That has already happened once here —
     * the removal event was pinned to the TOTP flow id, so a second factor removed by any other
     * means would not have been classified.
     *
     * The structural rule below closes that gap for the case that matters most: any
     * `account.mfa.<factor>.<verb>` event whose verb removes a factor is high severity whether or
     * not a constant for it exists yet. It errs towards over-alerting, which is the correct
     * direction for this particular decision.
     */
    fun isHighSeverity(eventType: String): Boolean =
        eventType in HIGH_SEVERITY || removesSecondFactor(eventType)

    private fun removesSecondFactor(eventType: String): Boolean =
        eventType.startsWith(MFA_EVENT_PREFIX) &&
            eventType.substringAfterLast('.') in FACTOR_REMOVAL_VERBS
}

/**
 * Metric names, from concept §7.5.
 *
 * The comment on cardinality is the important part: a label whose value comes from user input
 * will eventually blow up the metrics backend, so labels are restricted to closed sets.
 */
object MetricNames {

    const val LOGIN_ATTEMPTS = "auth_login_attempts_total"
    const val LOGIN_FAILURES = "auth_login_failures_total"
    const val MFA_CHALLENGES = "auth_mfa_challenges_total"

    /**
     * Logins that skipped the second factor on a trusted device.
     *
     * Meaningful only next to [MFA_CHALLENGES]: this feature legitimately drives challenges down,
     * so a fall in that counter is only alarming when this one does not rise to meet it.
     */
    const val TRUSTED_DEVICE_SKIPS = "auth_trusted_device_skips_total"
    const val TRUSTED_DEVICE_REUSE_DETECTED = "auth_trusted_device_reuse_detected_total"
    const val REFRESH_REUSE_DETECTED = "auth_refresh_reuse_detected_total"
    const val OAUTH_CALLBACK_FAILURES = "oauth_callback_failures_total"
    const val PASSWORD_HASH_DURATION = "password_hash_duration_seconds"
    const val PROVIDER_LATENCY = "provider_latency_seconds"
    const val RATE_LIMIT_REJECTIONS = "rate_limit_rejections_total"
    const val OUTBOX_DELIVERY_FAILURES = "outbox_delivery_failures_total"
    const val OUTBOX_PENDING = "outbox_pending_events"
    const val FLOW_EXECUTIONS = "helium_flow_executions_total"

    /**
     * Labels that may be attached to a metric.
     *
     * Never an email address, username, user id, IP or token id — concept §7.5: "Do not use
     * raw email addresses or usernames as high-cardinality metric labels."
     */
    val ALLOWED_LABELS: Set<String> = setOf("flow", "outcome", "provider", "client_id", "dimension", "error")
}

/**
 * Risk signals that raise the bar for an authentication attempt.
 *
 * Deliberately small. Concept §4.6 warns against permanent lockouts as the only control, and
 * §4.10 lists the responses that actually work: step-up, notification, progressive delay.
 * Anything cleverer needs data this system does not yet collect.
 */
enum class RiskSignal {
    /** No active session for this account has ever come from this user-agent hash. */
    NEW_DEVICE,

    /** The account failed several times before this attempt. */
    RECENT_FAILURES,

    /** A used refresh token was presented — treat everything about the account as suspect. */
    TOKEN_REUSE,

    /** Repeated failures across many accounts from one address. */
    CREDENTIAL_STUFFING_PATTERN,
    ;
}

/** What to do about a set of [RiskSignal]s. */
enum class RiskResponse {
    ALLOW,

    /** Proceed, but notify the account owner. */
    NOTIFY,

    /** Demand a second factor even where policy would not normally require one. */
    STEP_UP,

    /** Refuse and require a recovery flow. */
    BLOCK,
}

/**
 * Maps signals to a response.
 *
 * Conservative on purpose: only token reuse blocks outright, because false positives here lock
 * real users out of their accounts and the concept is explicit that denial of service is the
 * failure mode to avoid.
 */
fun evaluateRisk(signals: Set<RiskSignal>): RiskResponse = when {
    RiskSignal.TOKEN_REUSE in signals -> RiskResponse.BLOCK
    RiskSignal.CREDENTIAL_STUFFING_PATTERN in signals -> RiskResponse.STEP_UP
    RiskSignal.RECENT_FAILURES in signals && RiskSignal.NEW_DEVICE in signals -> RiskResponse.STEP_UP
    RiskSignal.NEW_DEVICE in signals -> RiskResponse.NOTIFY
    else -> RiskResponse.ALLOW
}
