package dev.kamiql.helium.flow

import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.domain.error.AuthError
import java.time.Instant

/**
 * The three things a flow can do: finish, ask for more proof, or refuse.
 *
 * "Ask for more proof" is a first-class outcome rather than an error, because MFA and consent
 * are normal parts of a successful journey. Modelling them as failures is what leads to routes
 * that special-case status codes.
 */
sealed interface FlowResult<out R> {

    data class Success<R>(val value: R) : FlowResult<R>

    /**
     * The caller must complete a challenge and retry.
     *
     * @param transactionId opaque handle for the short-lived, single-use transaction.
     * @param methods which challenges are available, e.g. `totp`, `recovery_code`.
     */
    data class Challenge(
        val code: String,
        val transactionId: TransactionId,
        val expiresAt: Instant,
        val methods: Set<String> = emptySet(),
    ) : FlowResult<Nothing>

    /**
     * The flow refused.
     *
     * @param redirect set only for OAuth protocol failures that RFC 6749 requires to be
     *        reported back to a **pre-validated** redirect URI. Never populated from
     *        unvalidated client input.
     */
    data class Failure(
        val error: AuthError,
        val redirect: ProtocolRedirect? = null,
    ) : FlowResult<Nothing>
}

/**
 * An OAuth error that must be delivered to the client's registered redirect URI.
 *
 * Only constructed after the redirect URI has been matched exactly against the client's
 * allowlist. If validation of the client or the URI itself failed, the error is rendered
 * directly instead — redirecting there would be an open redirect (concept §4.9).
 */
data class ProtocolRedirect(
    val redirectUri: String,
    val error: String,
    val errorDescription: String?,
    val state: String?,
)

/** Convenience for the common "map the value, keep everything else" case. */
inline fun <A, B> FlowResult<A>.map(transform: (A) -> B): FlowResult<B> = when (this) {
    is FlowResult.Success -> FlowResult.Success(transform(value))
    is FlowResult.Challenge -> this
    is FlowResult.Failure -> this
}
