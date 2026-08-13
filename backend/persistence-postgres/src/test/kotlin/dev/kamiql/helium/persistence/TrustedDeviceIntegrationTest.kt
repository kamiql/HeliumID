package dev.kamiql.helium.persistence

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.TrustedDeviceId
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.session.TrustedDevice
import dev.kamiql.helium.domain.session.TrustedDeviceRevocationReason
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.persistence.repository.TrustedDeviceRepositoryImpl
import dev.kamiql.helium.persistence.repository.UserRepositoryImpl
import dev.kamiql.helium.testing.PostgresFixture
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.sql.SQLException
import java.sql.Types
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Integration tests for [TrustedDeviceRepositoryImpl] against a real PostgreSQL.
 *
 * A trusted device is a *deliberate reduction in assurance*: presenting the cookie lets the next
 * login skip MFA. Everything that keeps that reduction bounded lives in the database — the
 * `(user_id, hash)` predicate that stops a token crossing accounts, the conditional UPDATE that
 * makes rotation atomic, the CHECK constraints that stop a half-revoked row existing, and the
 * cascade that removes the device with its owner. None of those can be tested against a mock, so
 * they are tested here.
 *
 * Tagged `integration` like its siblings, so `./gradlew build` stays fast and offline; run with
 * `./gradlew integrationTest`.
 */
@Tag("integration")
class TrustedDeviceIntegrationTest {

    private val db = PostgresFixture.db
    private val users = UserRepositoryImpl(db)
    private val devices = TrustedDeviceRepositoryImpl(db)

    private val now: Instant = Instant.parse("2026-08-12T10:00:00Z")

    /** One hour on: the instant a rotation or revocation happens, distinct from [now]. */
    private val later: Instant = now.plusSeconds(3_600)

    /** The absolute trust window. Rotation must never move this. */
    private val expiry: Instant = now.plusSeconds(30L * 86_400)

    @BeforeEach
    fun reset() {
        // `trusted_devices` is not named in the fixture's TRUNCATE list, but it carries a foreign
        // key to `users`, so `RESTART IDENTITY CASCADE` empties it too. Asserted below rather than
        // assumed, because a silent carry-over between tests would make the counting assertions
        // (revokeAllForUser, deleteExpired) pass or fail for the wrong reason.
        PostgresFixture.truncateAll()
        assertEquals(0, countDevices(), "the fixture must leave no trusted devices behind")
    }

    // -----------------------------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------------------------

    @Test
    fun `insert round trips every column including the nullable ones`(): Unit = runBlocking {
        val user = users.insert(newUser("alice"))

        val populated = devices.insert(
            newDevice(
                userId = user.id,
                tokenHash = "hash-populated",
                previousTokenHash = "hash-superseded",
                label = "Firefox on Fedora",
                lastUsedAt = later,
                revokedAt = later,
                revokedReason = TrustedDeviceRevocationReason.USER_REVOKED,
            ),
        )
        // Every nullable column left null: the shape a freshly minted device actually has.
        val bare = devices.insert(newDevice(user.id, "hash-bare"))

        assertEquals(populated, assertNotNull(devices.findByHash(user.id, "hash-populated")))

        val loadedBare = assertNotNull(devices.findByHash(user.id, "hash-bare"))
        assertEquals(bare, loadedBare)
        assertNull(loadedBare.previousTokenHash)
        assertNull(loadedBare.label)
        assertNull(loadedBare.revokedAt)
        assertNull(loadedBare.revokedReason)
        // timestamptz must come back as the same instant, not shifted by the JVM's zone.
        assertEquals(now, loadedBare.createdAt)
        assertEquals(expiry, loadedBare.expiresAt)
    }

    @Test
    fun `a device token minted for one account cannot be presented on another`(): Unit = runBlocking {
        val owner = users.insert(newUser("bob"))
        val attacker = users.insert(newUser("mallory"))
        devices.insert(newDevice(owner.id, "hash-owner"))

        // Token substitution: the attacker knows a valid device token but not whose it is. If the
        // lookup were keyed on the hash alone, this would hand them an MFA bypass on their own
        // account — and every hash in a leaked table would be a usable second factor.
        assertNull(devices.findByHash(attacker.id, "hash-owner"))
        assertNotNull(devices.findByHash(owner.id, "hash-owner"))
    }

    @Test
    fun `the superseded generation is found even when the device is already revoked`(): Unit = runBlocking {
        val user = users.insert(newUser("carol"))

        devices.insert(newDevice(user.id, "live-current", previousTokenHash = "live-previous"))
        devices.insert(
            newDevice(
                userId = user.id,
                tokenHash = "revoked-current",
                previousTokenHash = "revoked-previous",
                revokedAt = later,
                revokedReason = TrustedDeviceRevocationReason.MFA_CHANGED,
            ),
        )

        assertEquals("live-current", assertNotNull(devices.findByPreviousHash(user.id, "live-previous")).tokenHash)

        // The revoked row must still match: a copied cookie replayed after the device was revoked
        // is the same theft, and filtering it out here would make reuse detection depend on the
        // order in which the victim and the thief happen to log in.
        val reused = assertNotNull(devices.findByPreviousHash(user.id, "revoked-previous"))
        assertEquals("revoked-current", reused.tokenHash)
        assertNotNull(reused.revokedAt)

        // Scoped to the owner for the same reason findByHash is.
        val stranger = users.insert(newUser("dave"))
        assertNull(devices.findByPreviousHash(stranger.id, "live-previous"))
    }

    // -----------------------------------------------------------------------------------------
    // Rotation
    // -----------------------------------------------------------------------------------------

    @Test
    fun `rotation advances the token and leaves the trust window untouched`(): Unit = runBlocking {
        val user = users.insert(newUser("erin"))
        val device = devices.insert(newDevice(user.id, "generation-1", label = "Pixel 9"))

        assertTrue(devices.rotate(device.id, "generation-1", "generation-2", later))

        val rotated = assertNotNull(devices.findByHash(user.id, "generation-2"))
        assertEquals("generation-1", rotated.previousTokenHash)
        assertEquals(later, rotated.lastUsedAt)
        // The point of the whole record: use renews the credential, never the trust. A sliding
        // expiry would turn "trusted for 30 days" into "trusted forever", i.e. MFA switched off.
        assertEquals(expiry, rotated.expiresAt)
        assertEquals(device.createdAt, rotated.createdAt)
        assertEquals("Pixel 9", rotated.label)

        // The old value must no longer authenticate, only incriminate.
        assertNull(devices.findByHash(user.id, "generation-1"))
        assertEquals(device.id, assertNotNull(devices.findByPreviousHash(user.id, "generation-1")).id)
    }

    @Test
    fun `rotation fails on a stale expected hash and on a revoked device`(): Unit = runBlocking {
        val user = users.insert(newUser("frank"))

        val device = devices.insert(newDevice(user.id, "current-hash"))
        // A caller holding a hash the row no longer carries has, by definition, an out-of-date
        // cookie: it was already rotated away, so minting a successor from it would create a
        // second live token for one device.
        assertFalse(devices.rotate(device.id, "some-other-hash", "successor", later))
        assertNotNull(devices.findByHash(user.id, "current-hash"), "the failed rotation must not have written")
        assertNull(devices.findByHash(user.id, "successor"))

        val revoked = devices.insert(
            newDevice(
                userId = user.id,
                tokenHash = "revoked-hash",
                revokedAt = now,
                revokedReason = TrustedDeviceRevocationReason.PASSWORD_CHANGED,
            ),
        )
        // Revocation has to be terminal. If a revoked row could rotate, "revoke this device" would
        // last exactly until the device's next login.
        assertFalse(devices.rotate(revoked.id, "revoked-hash", "resurrected", later))
        assertNull(devices.findByHash(user.id, "resurrected"))
    }

    @Test
    fun `only one concurrent rotation of the same device can succeed`(): Unit = runBlocking {
        val user = users.insert(newUser("grace"))
        val device = devices.insert(newDevice(user.id, "contested-hash"))

        // Eight logins present the same cookie at the same instant — the victim and a thief who
        // copied it, or simply a client retrying. Reuse detection rests entirely on there being
        // exactly one valid successor: if two rotations both won, two live tokens would exist for
        // one device and the "old value presented again" signal would fire on legitimate traffic
        // (or, worse, never fire on stolen traffic).
        val outcomes = coroutineScope {
            (1..8).map { attempt ->
                async { attempt to devices.rotate(device.id, "contested-hash", "successor-$attempt", later) }
            }.awaitAll()
        }

        val winners = outcomes.filter { it.second }
        assertEquals(1, winners.size, "exactly one rotation must succeed")
        assertEquals(7, outcomes.count { !it.second })

        val stored = assertNotNull(devices.findByHash(user.id, "successor-${winners.single().first}"))
        assertEquals("contested-hash", stored.previousTokenHash)
        // No loser may have left a row of its own behind.
        assertEquals(1, countDevices())
    }

    // -----------------------------------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------------------------------

    @Test
    fun `revocation is scoped to the owning user`(): Unit = runBlocking {
        val owner = users.insert(newUser("heidi"))
        val stranger = users.insert(newUser("ivan"))
        val device = devices.insert(newDevice(owner.id, "owned-hash"))

        // Device ids reach the API from the account UI, so "revoke device X" must not become a
        // cross-account write for anyone who can guess or observe a UUID.
        assertFalse(devices.revoke(stranger.id, device.id, later, TrustedDeviceRevocationReason.USER_REVOKED))
        assertNull(assertNotNull(devices.findByHash(owner.id, "owned-hash")).revokedAt)

        assertTrue(devices.revoke(owner.id, device.id, later, TrustedDeviceRevocationReason.USER_REVOKED))
        assertNotNull(assertNotNull(devices.findByHash(owner.id, "owned-hash")).revokedAt)
    }

    @Test
    fun `re-revoking keeps the original timestamp and reason`(): Unit = runBlocking {
        val user = users.insert(newUser("judy"))
        val device = devices.insert(newDevice(user.id, "double-revoke-hash"))

        assertTrue(devices.revoke(user.id, device.id, now, TrustedDeviceRevocationReason.REUSE_DETECTED))
        // A later USER_REVOKED must not overwrite the earlier REUSE_DETECTED: the first
        // revocation is the incident record, and an ordinary "sign out this device" click
        // afterwards would otherwise erase the evidence that the cookie was stolen.
        assertFalse(devices.revoke(user.id, device.id, later, TrustedDeviceRevocationReason.USER_REVOKED))

        val stored = assertNotNull(devices.findByHash(user.id, "double-revoke-hash"))
        assertEquals(now, stored.revokedAt)
        assertEquals(TrustedDeviceRevocationReason.REUSE_DETECTED, stored.revokedReason)
    }

    @Test
    fun `an ordinary revocation keeps the superseded hash so a later replay is still caught`(): Unit = runBlocking {
        val user = users.insert(newUser("karl"))
        val single = devices.insert(newDevice(user.id, "single-hash", previousTokenHash = "single-previous"))
        devices.insert(newDevice(user.id, "bulk-hash", previousTokenHash = "bulk-previous"))

        assertTrue(devices.revoke(user.id, single.id, later, TrustedDeviceRevocationReason.USER_REVOKED))
        assertEquals(1, devices.revokeAllForUser(user.id, later, TrustedDeviceRevocationReason.PASSWORD_CHANGED))

        // The point of the whole exercise: someone copied the cookie, then the owner changed
        // their password for unrelated reasons. The replay that follows must still read as reuse.
        // Clearing the hash on every revocation would make detection depend on which of the two
        // happened to act first.
        assertEquals("single-previous", assertNotNull(devices.findByHash(user.id, "single-hash")).previousTokenHash)
        assertEquals("bulk-previous", assertNotNull(devices.findByHash(user.id, "bulk-hash")).previousTokenHash)
        assertNotNull(devices.findByPreviousHash(user.id, "single-previous"))
        assertNotNull(devices.findByPreviousHash(user.id, "bulk-previous"))
    }

    @Test
    fun `revoking for reuse drops the superseded hash so the thief cannot re-trigger the alert`(): Unit = runBlocking {
        val user = users.insert(newUser("karla"))
        val device = devices.insert(newDevice(user.id, "reused-hash", previousTokenHash = "reused-previous"))

        assertTrue(devices.revoke(user.id, device.id, later, TrustedDeviceRevocationReason.REUSE_DETECTED))

        // The theft is already recorded and the owner already notified. Leaving the value indexed
        // would hand whoever holds the stolen cookie a way to send a fresh security mail on every
        // retry.
        assertNull(assertNotNull(devices.findByHash(user.id, "reused-hash")).previousTokenHash)
        assertNull(devices.findByPreviousHash(user.id, "reused-previous"))
    }

    @Test
    fun `revokeAllForUser counts the live devices and spares other accounts`(): Unit = runBlocking {
        val user = users.insert(newUser("lena"))
        val bystander = users.insert(newUser("mike"))

        devices.insert(newDevice(user.id, "live-1"))
        devices.insert(newDevice(user.id, "live-2"))
        devices.insert(
            newDevice(
                userId = user.id,
                tokenHash = "already-revoked",
                revokedAt = now,
                revokedReason = TrustedDeviceRevocationReason.REUSE_DETECTED,
            ),
        )
        devices.insert(newDevice(bystander.id, "bystander-hash"))

        // The count feeds the audit event and the "N devices signed out" mail, so counting a row
        // that was already dead would misreport the blast radius of a password change.
        assertEquals(2, devices.revokeAllForUser(user.id, later, TrustedDeviceRevocationReason.PASSWORD_CHANGED))

        assertEquals(TrustedDeviceRevocationReason.PASSWORD_CHANGED, reasonOf(user.id, "live-1"))
        assertEquals(TrustedDeviceRevocationReason.PASSWORD_CHANGED, reasonOf(user.id, "live-2"))
        assertEquals(now, assertNotNull(devices.findByHash(user.id, "already-revoked")).revokedAt)
        assertEquals(TrustedDeviceRevocationReason.REUSE_DETECTED, reasonOf(user.id, "already-revoked"))
        assertNull(assertNotNull(devices.findByHash(bystander.id, "bystander-hash")).revokedAt)

        // Nothing left to revoke on a second pass.
        assertEquals(0, devices.revokeAllForUser(user.id, later, TrustedDeviceRevocationReason.PASSWORD_CHANGED))
    }

    // -----------------------------------------------------------------------------------------
    // Listing and cleanup
    // -----------------------------------------------------------------------------------------

    @Test
    fun `listActiveForUser hides expired and revoked devices, most recently used first`(): Unit = runBlocking {
        val user = users.insert(newUser("nina"))
        val bystander = users.insert(newUser("oscar"))

        devices.insert(newDevice(user.id, "used-oldest", lastUsedAt = now.minusSeconds(7_200)))
        devices.insert(newDevice(user.id, "used-newest", lastUsedAt = now.minusSeconds(60)))
        devices.insert(newDevice(user.id, "used-middle", lastUsedAt = now.minusSeconds(1_800)))
        devices.insert(newDevice(user.id, "expired", expiresAt = now.minusSeconds(1)))
        devices.insert(
            newDevice(
                userId = user.id,
                tokenHash = "revoked",
                revokedAt = now.minusSeconds(10),
                revokedReason = TrustedDeviceRevocationReason.ADMIN_ACTION,
            ),
        )
        devices.insert(newDevice(bystander.id, "someone-elses"))

        // This list is what the account UI shows as "devices that may skip MFA". A revoked or
        // expired row appearing here would tell the user a factor is still deferred when it is
        // not — and hiding a live one would hide a real bypass.
        val active = devices.listActiveForUser(user.id, now)
        assertEquals(listOf("used-newest", "used-middle", "used-oldest"), active.map { it.tokenHash })
    }

    @Test
    fun `deleteExpired removes lapsed devices but keeps unexpired reuse evidence`(): Unit = runBlocking {
        val user = users.insert(newUser("peggy"))

        devices.insert(newDevice(user.id, "long-expired", expiresAt = now.minusSeconds(86_400)))
        devices.insert(newDevice(user.id, "just-expired", expiresAt = now.minusSeconds(1)))
        devices.insert(newDevice(user.id, "still-valid", expiresAt = now.plusSeconds(1)))
        devices.insert(
            newDevice(
                userId = user.id,
                tokenHash = "reuse-detected",
                expiresAt = expiry,
                revokedAt = now,
                revokedReason = TrustedDeviceRevocationReason.REUSE_DETECTED,
            ),
        )

        assertEquals(2, devices.deleteExpired(now))

        assertNull(devices.findByHash(user.id, "long-expired"))
        assertNull(devices.findByHash(user.id, "just-expired"))
        assertNotNull(devices.findByHash(user.id, "still-valid"))
        // The cleanup job must key on expiry alone. A row revoked for REUSE_DETECTED is the
        // record of a detected cookie theft; deleting it early would let the same stolen cookie
        // be replayed later as an unknown one, and would erase what the security notification
        // referred to.
        assertNotNull(devices.findByHash(user.id, "reuse-detected"))
    }

    // -----------------------------------------------------------------------------------------
    // Schema invariants
    // -----------------------------------------------------------------------------------------

    @Test
    fun `the schema rejects a half-revoked row and an unknown reason`(): Unit = runBlocking {
        val user = users.insert(newUser("quinn"))

        // `revoked_at` without a reason: a device that stopped being trusted for no recorded
        // cause. Every revocation feeds an audit event, so the reason cannot be optional.
        val missingReason = assertFailsWith<SQLException> {
            insertRawDevice(user.id, "no-reason", revokedAt = later, revokedReason = null)
        }
        assertTrue(
            missingReason.message.orEmpty().contains("trusted_devices_revocation_check"),
            "expected the revocation CHECK to fire, got: ${missingReason.message}",
        )

        // A reason without `revoked_at`: a live row that reads as revoked. Whichever way the
        // application then interprets it, one of the two columns is lying.
        val missingTimestamp = assertFailsWith<SQLException> {
            insertRawDevice(user.id, "no-timestamp", revokedAt = null, revokedReason = "USER_REVOKED")
        }
        assertTrue(
            missingTimestamp.message.orEmpty().contains("trusted_devices_revocation_check"),
            "expected the revocation CHECK to fire, got: ${missingTimestamp.message}",
        )

        // An unknown reason. The mapper decodes this column with a `runCatching`, so a value the
        // enum does not know would silently read back as `null` — a revoked device with no
        // reason. The constraint is what stops that state ever reaching the row.
        val unknownReason = assertFailsWith<SQLException> {
            insertRawDevice(user.id, "bogus-reason", revokedAt = later, revokedReason = "NOT_A_REASON")
        }
        assertTrue(
            unknownReason.message.orEmpty().contains("trusted_devices_reason_check"),
            "expected the reason CHECK to fire, got: ${unknownReason.message}",
        )

        assertEquals(0, countDevices(), "no rejected row may have been written")
    }

    @Test
    fun `deleting the owning user takes the trusted device with it`(): Unit = runBlocking {
        val user = users.insert(newUser("rita"))
        devices.insert(newDevice(user.id, "orphan-candidate"))

        // Hard deletion is the erasure path. A device row surviving its owner would be a token
        // that authenticates against an account that no longer exists, and — because `user_id` is
        // the only binding — would be reachable again if that UUID were ever reissued.
        deleteUserRow(user.id)

        assertNull(devices.findByHash(user.id, "orphan-candidate"))
        assertEquals(0, countDevices())
    }

    // -----------------------------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------------------------

    private fun newUser(name: String): User = User(
        id = UserId.random(),
        username = requireNotNull(Username.parse(name)),
        primaryEmail = requireNotNull(EmailAddress.parse("$name@example.com")),
        firstName = "Test",
        lastName = "User",
        status = UserStatus.ACTIVE,
        emailVerifiedAt = now,
        createdAt = now,
        updatedAt = now,
        version = 0,
    )

    private fun newDevice(
        userId: UserId,
        tokenHash: String,
        previousTokenHash: String? = null,
        label: String? = null,
        lastUsedAt: Instant = now,
        expiresAt: Instant = expiry,
        revokedAt: Instant? = null,
        revokedReason: TrustedDeviceRevocationReason? = null,
    ): TrustedDevice = TrustedDevice(
        id = TrustedDeviceId.random(),
        userId = userId,
        tokenHash = tokenHash,
        previousTokenHash = previousTokenHash,
        label = label,
        createdAt = now,
        lastUsedAt = lastUsedAt,
        expiresAt = expiresAt,
        revokedAt = revokedAt,
        revokedReason = revokedReason,
    )

    private suspend fun reasonOf(userId: UserId, tokenHash: String): TrustedDeviceRevocationReason? =
        assertNotNull(devices.findByHash(userId, tokenHash)).revokedReason

    /**
     * Inserts a row bypassing the repository, so states the Kotlin types cannot express — a
     * revocation reason outside the enum, or half of a revocation — can be handed to the database
     * and rejected by it.
     */
    private fun insertRawDevice(
        userId: UserId,
        tokenHash: String,
        revokedAt: Instant?,
        revokedReason: String?,
    ) {
        PostgresFixture.container.createConnection("").use { connection ->
            connection.prepareStatement(
                """
                INSERT INTO trusted_devices
                    (id, user_id, token_hash, previous_token_hash, label,
                     created_at, last_used_at, expires_at, revoked_at, revoked_reason)
                VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?)
                """.trimIndent(),
            ).use { statement ->
                statement.setObject(1, UUID.randomUUID())
                statement.setObject(2, userId.value)
                statement.setString(3, tokenHash)
                statement.setObject(4, now.atOffset(ZoneOffset.UTC))
                statement.setObject(5, now.atOffset(ZoneOffset.UTC))
                statement.setObject(6, expiry.atOffset(ZoneOffset.UTC))
                if (revokedAt == null) {
                    statement.setNull(7, Types.TIMESTAMP_WITH_TIMEZONE)
                } else {
                    statement.setObject(7, revokedAt.atOffset(ZoneOffset.UTC))
                }
                statement.setString(8, revokedReason)
                statement.executeUpdate()
            }
        }
    }

    /** Hard delete, which [UserRepositoryImpl] deliberately does not offer — it only soft-deletes. */
    private fun deleteUserRow(userId: UserId) {
        PostgresFixture.container.createConnection("").use { connection ->
            connection.prepareStatement("DELETE FROM users WHERE id = ?").use { statement ->
                statement.setObject(1, userId.value)
                statement.executeUpdate()
            }
        }
    }

    private fun countDevices(): Int =
        PostgresFixture.container.createConnection("").use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery("SELECT count(*) FROM trusted_devices").use { rows ->
                    rows.next()
                    rows.getInt(1)
                }
            }
        }
}
