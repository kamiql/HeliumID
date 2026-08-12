package dev.kamiql.helium.redis

import dev.kamiql.helium.domain.common.TransactionId
import dev.kamiql.helium.flow.port.SecurityTransactionStore
import io.lettuce.core.api.async.RedisAsyncCommands
import kotlinx.coroutines.future.await
import org.slf4j.LoggerFactory
import java.time.Duration

/**
 * Redis-backed store for short-lived, single-use security transactions.
 *
 * The kind is part of the key, so an OAuth `state` handle cannot be redeemed as an MFA
 * transaction even if the identifiers collide.
 *
 * Losing this store is a availability problem, not a security one: every entry is short lived
 * and its absence makes the operation fail closed. Nothing durable depends on it (§3.1).
 */
class RedisSecurityTransactionStore(
    private val commands: RedisAsyncCommands<String, String>,
    private val keyPrefix: String = "helium:tx:",
) : SecurityTransactionStore {

    private val log = LoggerFactory.getLogger(RedisSecurityTransactionStore::class.java)

    override suspend fun put(id: TransactionId, kind: String, payload: String, ttl: Duration) {
        commands.psetex(key(id, kind), ttl.toMillis(), payload).await()
    }

    override suspend fun peek(id: TransactionId, kind: String): String? =
        runCatching { commands.get(key(id, kind)).await() }
            .onFailure { log.error("transaction store unavailable", it) }
            .getOrNull()

    /**
     * Atomic read-and-delete.
     *
     * `GETDEL` is what makes an authorization `state`, an MFA transaction and a provider
     * linking handle genuinely single-use: two concurrent redemptions cannot both observe the
     * value. Doing this as GET followed by DEL would reintroduce exactly the replay window
     * these transactions exist to close.
     */
    override suspend fun take(id: TransactionId, kind: String): String? =
        runCatching { commands.getdel(key(id, kind)).await() }
            .onFailure { log.error("transaction store unavailable", it) }
            .getOrNull()

    override suspend fun delete(id: TransactionId, kind: String) {
        runCatching { commands.del(key(id, kind)).await() }
    }

    override suspend fun increment(id: TransactionId, kind: String, ttl: Duration): Long {
        val counterKey = "${key(id, kind)}:n"
        val value = commands.incr(counterKey).await()
        if (value == 1L) commands.pexpire(counterKey, ttl.toMillis()).await()
        return value
    }

    private fun key(id: TransactionId, kind: String) = "$keyPrefix$kind:${id.value}"
}

/**
 * In-memory equivalent for tests and single-node development.
 *
 * [take] is synchronized on the map so it keeps the single-use guarantee within one process.
 */
class InMemorySecurityTransactionStore(
    private val clock: () -> Long = System::currentTimeMillis,
) : SecurityTransactionStore {

    private data class Entry(val payload: String, val expiresAt: Long)

    private val entries = java.util.concurrent.ConcurrentHashMap<String, Entry>()
    private val counters = java.util.concurrent.ConcurrentHashMap<String, Long>()

    override suspend fun put(id: TransactionId, kind: String, payload: String, ttl: Duration) {
        entries[key(id, kind)] = Entry(payload, clock() + ttl.toMillis())
    }

    override suspend fun peek(id: TransactionId, kind: String): String? = read(key(id, kind))

    override suspend fun take(id: TransactionId, kind: String): String? {
        val composite = key(id, kind)
        val entry = entries.remove(composite) ?: return null
        return if (entry.expiresAt > clock()) entry.payload else null
    }

    override suspend fun delete(id: TransactionId, kind: String) {
        entries.remove(key(id, kind))
    }

    override suspend fun increment(id: TransactionId, kind: String, ttl: Duration): Long =
        counters.merge("${key(id, kind)}:n", 1L, Long::plus)!!

    private fun read(composite: String): String? {
        val entry = entries[composite] ?: return null
        if (entry.expiresAt <= clock()) {
            entries.remove(composite)
            return null
        }
        return entry.payload
    }

    private fun key(id: TransactionId, kind: String) = "$kind:${id.value}"
}

/** Kinds used across the system. Constants rather than literals so typos fail at compile time. */
object TransactionKind {
    const val MFA_CHALLENGE: String = "mfa"
    const val PROVIDER_AUTHORIZATION: String = "provider-auth"
    const val PROVIDER_LINK: String = "provider-link"
    const val CONSENT: String = "consent"
    const val TOTP_ENROLLMENT: String = "totp-enroll"
}
