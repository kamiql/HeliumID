package dev.kamiql.helium.flow

import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.RequestId
import dev.kamiql.helium.domain.policy.Principal
import java.time.Instant

/**
 * Everything a flow may know about the caller.
 *
 * Passed explicitly into every requirement and step. There is no ambient "current user" — a
 * global mutable security context is the single easiest way to authorize the wrong subject,
 * and CLAUDE.md forbids it.
 *
 * @param actor who is making the request. [Principal.Anonymous] rather than `null`, so an
 *        unauthenticated caller is a value you must handle, not an absence you can forget.
 * @param ipAddress already unwrapped from `X-Forwarded-For`, and only when a trusted proxy is
 *        configured. Used for rate limiting and hashed before storage — never logged raw.
 * @param idempotencyKey client-supplied key; required by flows that declare
 *        [IdempotencyPolicy.Required].
 * @param now captured once at the start of the request so every expiry check inside one flow
 *        sees the same instant. A flow that read the clock twice could accept a token in step
 *        two that it rejected in step one.
 */
data class FlowContext(
    val requestId: RequestId,
    val actor: Principal,
    val clientId: ClientId? = null,
    val ipAddress: String? = null,
    val userAgent: String? = null,
    val idempotencyKey: String? = null,
    val now: Instant,
    /** Origin header, for CSRF diagnostics recorded in the audit trail. */
    val origin: String? = null,
) {
    /** Coarse device fingerprint used for "new device" detection. Never a stable tracker. */
    val deviceFingerprint: String?
        get() = userAgent?.let { "$it|${ipAddress.orEmpty()}" }
}
