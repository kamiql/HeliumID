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
    const val MFA_ENROLLED = "account.mfa.totp.confirm"
    const val MFA_DISABLED = "account.mfa.totp.disable"
    const val RECOVERY_CODES_REGENERATED = "account.mfa.recovery-codes.regenerate"

    // identities
    const val PROVIDER_LINKED = "identity.provider-linked"
    const val PROVIDER_UNLINKED = "account.provider.unlink"

    // protocol
    const val AUTHORIZE = "oauth.authorize"
    const val TOKEN_ISSUED = "oauth.token"
    const val TOKEN_REVOKED = "oauth.revoke"
    const val REFRESH_REUSE_DETECTED = "token.refresh-reuse-detected"

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
     */
    val HIGH_SEVERITY: Set<String> = setOf(
        REFRESH_REUSE_DETECTED,
        MFA_DISABLED,
        ADMIN_USER_STATUS_CHANGED,
        ADMIN_ROLES_ASSIGNED,
        CLIENT_SECRET_ROTATED,
    )
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
