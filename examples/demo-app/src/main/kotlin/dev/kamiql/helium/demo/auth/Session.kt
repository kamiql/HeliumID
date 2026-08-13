package dev.kamiql.helium.demo.auth

import dev.kamiql.helium.client.HeliumApiException
import dev.kamiql.helium.client.HeliumError
import dev.kamiql.helium.client.HeliumIdClient
import dev.kamiql.helium.client.Pkce
import dev.kamiql.helium.client.TokenEndpointResponse
import dev.kamiql.helium.client.UserResponse
import dev.kamiql.helium.demo.DemoConfig
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * The browser's half of a signed-in session: an opaque id and nothing else.
 *
 * Everything of value — access token, refresh token, the user's claims — stays in [SessionStore]
 * on the server. The cookie carries no token, so an XSS bug in this application cannot exfiltrate
 * a credential that works against HeliumID, and `localStorage` never enters the picture.
 */
@kotlinx.serialization.Serializable
data class SessionCookie(val id: String)

/** The pending half of a login, held between `/login` and `/callback`. */
class LoginTransaction(
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val returnTo: String,
    val startedAt: Instant,
)

/**
 * A signed-in user, server side.
 *
 * [refreshLock] is not decoration. Refresh tokens rotate, and HeliumID treats a token presented
 * twice as theft: it revokes the entire family and signs the user out everywhere. Two concurrent
 * requests that both notice an expiring access token would do exactly that, so refreshes for one
 * session are serialized and the second caller finds the work already done.
 */
class DemoSession(
    val id: String,
    /** HeliumID's `sub`. The only stable identifier; usernames and emails can change. */
    val subject: String,
    @Volatile var accessToken: String,
    @Volatile var refreshToken: String?,
    @Volatile var accessTokenExpiresAt: Instant,
    @Volatile var grantedScopes: Set<String>,
    /** Claims from `/v1/me`, refreshed on demand. Permissions live here and in no token. */
    @Volatile var user: UserResponse,
    val authenticatedAt: Instant,
    internal val refreshLock: Mutex = Mutex(),
)

/**
 * In-memory session and login-transaction storage.
 *
 * A real deployment would put this in Redis or a database so sessions survive a restart and work
 * across instances. It is a map here because the subject of this example is the protocol, and a
 * second piece of infrastructure would only obscure it.
 */
class SessionStore(private val clock: () -> Instant = Instant::now) {

    private val sessions = ConcurrentHashMap<String, DemoSession>()
    private val transactions = ConcurrentHashMap<String, LoginTransaction>()

    /** Refresh this far before expiry, so a request never races the token it is about to use. */
    private val refreshMargin: Duration = Duration.ofSeconds(30)

    /** Abandoned login attempts are swept at this age. */
    private val transactionTtl: Duration = Duration.ofMinutes(10)

    // --- login transactions -----------------------------------------------------------

    /**
     * Starts a login and returns the opaque handle the cookie carries.
     *
     * The handle is *not* the `state` value. Putting `state` in the cookie and comparing it with
     * the query parameter would still work, but a separate handle means the callback can look up
     * the transaction without the browser ever holding the value being verified.
     */
    fun beginLogin(returnTo: String): Pair<String, LoginTransaction> {
        sweepTransactions()
        val handle = opaqueId()
        val transaction = LoginTransaction(
            state = Pkce.generateState(),
            nonce = Pkce.generateNonce(),
            codeVerifier = Pkce.generateVerifier(),
            returnTo = returnTo,
            startedAt = clock(),
        )
        transactions[handle] = transaction
        return handle to transaction
    }

    /**
     * Consumes a login transaction. Single use: a second callback with the same handle finds
     * nothing, which is what stops an authorization response from being replayed.
     */
    fun consumeLogin(handle: String?): LoginTransaction? {
        if (handle == null) return null
        val transaction = transactions.remove(handle) ?: return null
        return transaction.takeIf { clock().isBefore(it.startedAt.plus(transactionTtl)) }
    }

    private fun sweepTransactions() {
        val cutoff = clock().minus(transactionTtl)
        transactions.entries.removeIf { it.value.startedAt.isBefore(cutoff) }
    }

    // --- sessions ---------------------------------------------------------------------

    fun create(tokens: TokenEndpointResponse, subject: String, user: UserResponse): DemoSession {
        val session = DemoSession(
            id = opaqueId(),
            subject = subject,
            accessToken = tokens.accessToken,
            refreshToken = tokens.refreshToken,
            accessTokenExpiresAt = clock().plusSeconds(tokens.expiresIn),
            grantedScopes = tokens.grantedScopes,
            user = user,
            authenticatedAt = clock(),
        )
        sessions[session.id] = session
        return session
    }

    fun find(id: String?): DemoSession? = id?.let(sessions::get)

    fun remove(id: String?): DemoSession? = id?.let(sessions::remove)

    /**
     * A usable access token, refreshing first if it is about to expire.
     *
     * Returns `null` when the session can no longer be renewed — the caller signs the user out.
     * Every refresh failure is an `invalid_grant` and they are indistinguishable by design:
     * expired, revoked and reuse-detected all look the same, so the only correct response is to
     * stop using the session rather than retry.
     */
    suspend fun accessToken(session: DemoSession, client: HeliumIdClient, config: DemoConfig): String? {
        if (clock().isBefore(session.accessTokenExpiresAt.minus(refreshMargin))) {
            return session.accessToken
        }

        return session.refreshLock.withLock {
            // Re-check inside the lock: whoever held it before us may already have refreshed,
            // and refreshing again would present a token that is now spent.
            if (clock().isBefore(session.accessTokenExpiresAt.minus(refreshMargin))) {
                return@withLock session.accessToken
            }

            val current = session.refreshToken ?: return@withLock null
            val renewed = try {
                client.refresh(
                    refreshToken = current,
                    clientId = config.clientId,
                    clientSecret = config.clientSecret,
                )
            } catch (failure: HeliumApiException) {
                if (failure.error is HeliumError.InvalidGrant) {
                    // Never retry with the old value; presenting it again is what reuse
                    // detection is looking for.
                    sessions.remove(session.id)
                    return@withLock null
                }
                throw failure
            }

            // Persist the successor before anything can use the new access token: the old
            // refresh token is already spent server-side.
            session.refreshToken = renewed.refreshToken
            session.accessToken = renewed.accessToken
            session.accessTokenExpiresAt = clock().plusSeconds(renewed.expiresIn)
            session.grantedScopes = renewed.grantedScopes
            session.accessToken
        }
    }
}

/**
 * An opaque, unguessable identifier for a session or a pending login.
 *
 * Its own generator rather than `Pkce.generateState()`: these are not protocol values, and
 * borrowing a helper named for the OAuth `state` parameter would suggest they travel to HeliumID.
 * They never leave this application.
 */
private fun opaqueId(): String {
    val bytes = ByteArray(24)
    java.security.SecureRandom().nextBytes(bytes)
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
