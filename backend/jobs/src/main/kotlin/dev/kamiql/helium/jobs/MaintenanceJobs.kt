package dev.kamiql.helium.jobs

import dev.kamiql.helium.domain.crypto.HeliumClock
import dev.kamiql.helium.domain.repository.AuthorizationCodeRepository
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.domain.repository.RevokedTokenRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.VerificationTokenRepository
import dev.kamiql.helium.persistence.repository.IdempotencyStoreImpl
import dev.kamiql.helium.persistence.repository.OutboxDispatchRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.time.Duration

/**
 * Periodic cleanup and key rotation.
 *
 * Two rules govern what this deletes. Expired *credentials* go promptly: an expired
 * authorization code or reset token has no value and keeping it only grows the table. Security
 * *records* — audit rows, outbox failures, refresh-token families that recorded a reuse — are
 * kept, because concept §3.4 says not to delete security data immediately and because they are
 * the evidence for an investigation.
 *
 * @param retainProcessedOutboxFor how long delivered outbox rows stay queryable.
 */
class MaintenanceJobs(
    private val clock: HeliumClock,
    private val sessions: SessionRepository,
    private val verificationTokens: VerificationTokenRepository,
    private val authorizationCodes: AuthorizationCodeRepository,
    private val refreshTokens: RefreshTokenRepository,
    private val revokedTokens: RevokedTokenRepository,
    private val idempotency: IdempotencyStoreImpl,
    private val outbox: OutboxDispatchRepository,
    private val signingKeyRotation: SigningKeyRotation?,
    private val interval: Duration = Duration.ofHours(1),
    private val retainProcessedOutboxFor: Duration = Duration.ofDays(7),
) {

    private val log = LoggerFactory.getLogger(MaintenanceJobs::class.java)

    fun start(scope: CoroutineScope): Job = scope.launch {
        // Stagger the first run so a rolling restart does not have every instance sweeping at
        // the same moment.
        delay(Duration.ofMinutes(1).toMillis())
        while (isActive) {
            runCatching { runOnce() }.onFailure { log.error("maintenance sweep failed", it) }
            delay(interval.toMillis())
        }
    }

    /** One sweep. Exposed for tests and for a manual admin trigger. */
    suspend fun runOnce() {
        val now = clock.now()

        val expiredSessions = sessions.deleteExpired(now)
        val expiredVerification = verificationTokens.deleteExpired(now)
        val expiredCodes = authorizationCodes.deleteExpired(now)
        // Only families past their absolute expiry: a family revoked for reuse is retained
        // until then so the reuse timestamp survives long enough to be investigated.
        val expiredFamilies = refreshTokens.deleteExpired(now)
        val expiredRevocations = revokedTokens.deleteExpired(now)
        val expiredIdempotency = idempotency.deleteExpired(now)
        val prunedOutbox = outbox.deleteProcessedBefore(now.minus(retainProcessedOutboxFor))

        val stuck = outbox.countStuck(minAttempts = 10)
        if (stuck > 0) {
            // Loud, because a stuck outbox means security notifications are not being delivered.
            log.error("{} outbox event(s) have exhausted their retries and need attention", stuck)
        }

        signingKeyRotation?.runOnce(now)

        log.info(
            "maintenance sweep: sessions={} verification={} codes={} families={} revocations={} " +
                "idempotency={} outbox={}",
            expiredSessions, expiredVerification, expiredCodes, expiredFamilies,
            expiredRevocations, expiredIdempotency, prunedOutbox,
        )
    }
}

/**
 * Signing key lifecycle (concept §7.2).
 *
 * The sequence is generate → publish → wait → activate → wait → retire, and every wait exists
 * because verifiers cache JWKS. Activating a key the moment it is created would reject tokens
 * at any verifier whose cache is a few minutes old.
 *
 * @param rotateEvery how long a key signs before a successor is generated.
 * @param publishAhead how long a new key sits in JWKS before it starts signing. Must exceed
 *        the `Cache-Control` max-age on the JWKS response.
 */
class SigningKeyRotation(
    private val signingKeys: dev.kamiql.helium.oauth.SigningKeyService,
    private val repository: dev.kamiql.helium.domain.repository.SigningKeyRepository,
    private val rotateEvery: Duration = Duration.ofDays(30),
    private val publishAhead: Duration = Duration.ofHours(1),
) {

    private val log = LoggerFactory.getLogger(SigningKeyRotation::class.java)

    suspend fun runOnce(now: java.time.Instant) {
        val active = repository.findActive()

        // Promote a pending key that has been published long enough.
        val readyToPromote = repository.listPublishable()
            .filter { it.status == dev.kamiql.helium.domain.token.SigningKeyStatus.PENDING }
            .firstOrNull { it.createdAt.plus(publishAhead).isBefore(now) }

        if (readyToPromote != null) {
            log.info("promoting signing key {}", readyToPromote.id)
            signingKeys.promote(readyToPromote.id, now)
            return
        }

        // Generate a successor once the current key is old enough, but only if one is not
        // already waiting.
        val pendingExists = repository.listPublishable()
            .any { it.status == dev.kamiql.helium.domain.token.SigningKeyStatus.PENDING }
        val activeAge = active?.activatedAt ?: active?.createdAt
        if (!pendingExists && activeAge != null && activeAge.plus(rotateEvery).isBefore(now)) {
            val generated = signingKeys.generate(now)
            log.info("generated successor signing key {}; it will be promoted in {}", generated.id, publishAhead)
        }

        signingKeys.retireExpired(now)
    }
}
