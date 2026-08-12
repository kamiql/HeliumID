package dev.kamiql.helium.redis

import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimitDecision
import dev.kamiql.helium.flow.port.RateLimitKey
import dev.kamiql.helium.flow.port.RateLimiter
import io.lettuce.core.api.async.RedisAsyncCommands
import kotlinx.coroutines.future.await
import org.slf4j.LoggerFactory
import java.time.Duration

/**
 * Fixed-window counter in Redis.
 *
 * A fixed window can allow up to 2× the limit across a window boundary. That is accepted here:
 * the limits exist to make online guessing impractical, not to be exact, and a sliding-window
 * implementation costs a sorted set per key. Where precision matters more than cost — the
 * token endpoint under a paying client — raise the limit rather than change the algorithm.
 *
 * @param failClosed what to do when Redis is unreachable. Concept §7.6: "Rate limiting should
 *        degrade conservatively, not silently disable protection." Authentication endpoints
 *        pass `true`; a limiter used only for cosmetic throttling may pass `false`.
 */
class RedisRateLimiter(
    private val commands: RedisAsyncCommands<String, String>,
    private val keyPrefix: String = "helium:rl:",
    private val failClosed: Boolean = true,
) : RateLimiter {

    private val log = LoggerFactory.getLogger(RedisRateLimiter::class.java)

    override suspend fun consume(key: RateLimitKey, limit: RateLimit): RateLimitDecision {
        val redisKey = "$keyPrefix${key.dimension}:${key.value}"
        return try {
            val count = commands.incr(redisKey).await()
            if (count == 1L) {
                // First hit in this window starts the clock. If the process dies between INCR
                // and EXPIRE the key would leak, so the TTL is also refreshed defensively when
                // a key is found without one.
                commands.pexpire(redisKey, limit.window.toMillis()).await()
            } else if (count == 2L) {
                val ttl = commands.pttl(redisKey).await()
                if (ttl == null || ttl < 0) commands.pexpire(redisKey, limit.window.toMillis()).await()
            }

            if (count > limit.permits) {
                val ttlMillis = commands.pttl(redisKey).await() ?: limit.window.toMillis()
                RateLimitDecision.Limited(
                    Duration.ofMillis(ttlMillis.coerceAtLeast(1_000L)),
                )
            } else {
                RateLimitDecision.Allowed((limit.permits - count).toInt().coerceAtLeast(0))
            }
        } catch (error: Exception) {
            log.error("rate limiter backend unavailable for dimension {}", key.dimension, error)
            if (failClosed) {
                RateLimitDecision.Limited(Duration.ofSeconds(30))
            } else {
                RateLimitDecision.Allowed(0)
            }
        }
    }

    override suspend fun reset(key: RateLimitKey) {
        runCatching { commands.del("$keyPrefix${key.dimension}:${key.value}").await() }
            .onFailure { log.warn("failed to reset rate limit for {}", key.dimension, it) }
    }
}

/**
 * In-memory limiter for tests and single-node development.
 *
 * Not safe across instances, which is exactly why production wires [RedisRateLimiter]. It is
 * kept here rather than in test sources so a developer running without Redis still gets the
 * same behaviour, just not the same guarantees.
 */
class InMemoryRateLimiter(
    private val clock: () -> Long = System::currentTimeMillis,
) : RateLimiter {

    private data class Window(var count: Int, val resetAt: Long)

    private val windows = java.util.concurrent.ConcurrentHashMap<String, Window>()

    override suspend fun consume(key: RateLimitKey, limit: RateLimit): RateLimitDecision {
        val now = clock()
        val composite = "${key.dimension}:${key.value}"
        val window = windows.compute(composite) { _, existing ->
            if (existing == null || existing.resetAt <= now) {
                Window(1, now + limit.window.toMillis())
            } else {
                existing.also { it.count += 1 }
            }
        }!!
        return if (window.count > limit.permits) {
            RateLimitDecision.Limited(Duration.ofMillis((window.resetAt - now).coerceAtLeast(1_000)))
        } else {
            RateLimitDecision.Allowed(limit.permits - window.count)
        }
    }

    override suspend fun reset(key: RateLimitKey) {
        windows.remove("${key.dimension}:${key.value}")
    }
}
