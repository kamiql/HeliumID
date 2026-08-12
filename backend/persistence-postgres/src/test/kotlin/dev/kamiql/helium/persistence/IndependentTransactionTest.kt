package dev.kamiql.helium.persistence

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import dev.kamiql.helium.persistence.repository.UserRepositoryImpl
import dev.kamiql.helium.testing.PostgresFixture
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Regression tests for [TransactionManager.requiresNew][dev.kamiql.helium.flow.port.TransactionManager.requiresNew].
 *
 * This exists because of a real bug. Refresh-token reuse detection revoked the compromised token
 * family and then failed the request — and because the revocation shared the failing
 * transaction, it was rolled back with it. The replay was rejected, but the family stayed alive,
 * so an attacker replaying a stolen token paid no price at all. Only an end-to-end run against a
 * real database exposed it; every unit test passed.
 *
 * The property under test is narrow and easy to break again: work inside `requiresNew` must
 * survive the rollback of the transaction that surrounds it, and nothing else may.
 */
@Tag("integration")
class IndependentTransactionTest {

    private val db = PostgresFixture.db
    private val users = UserRepositoryImpl(db)
    private val transactions = ExposedTransactionManager(db)

    private val now: Instant = Instant.parse("2026-08-12T10:00:00Z")

    @BeforeEach
    fun reset() {
        PostgresFixture.truncateAll()
    }

    private fun newUser(name: String) = User(
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

    @Test
    fun `work in an independent transaction survives the outer rollback`(): Unit = runBlocking {
        val rolledBack = newUser("discarded")
        val committed = newUser("retained")

        assertFailsWith<IllegalStateException> {
            transactions.transaction {
                users.insert(rolledBack)

                // The compromise-response pattern: record the security consequence, then fail.
                transactions.requiresNew {
                    users.insert(committed)
                }

                error("the request fails after the security action was taken")
            }
        }

        assertNull(users.findById(rolledBack.id), "the outer write must be rolled back")
        assertNotNull(
            users.findById(committed.id),
            "the independent write must survive — this is the whole point of requiresNew",
        )
    }

    @Test
    fun `a nested ordinary transaction joins the outer one and rolls back with it`(): Unit = runBlocking {
        val user = newUser("nested")

        assertFailsWith<IllegalStateException> {
            transactions.transaction {
                transactions.transaction {
                    users.insert(user)
                }
                error("boom")
            }
        }

        // Nesting must join, not commit early. If this ever starts passing a non-null user, every
        // "all or nothing" guarantee in the flow engine is silently gone.
        assertNull(users.findById(user.id))
    }

    @Test
    fun `an independent transaction commits even when the outer one succeeds`(): Unit = runBlocking {
        val outer = newUser("outer")
        val inner = newUser("inner")

        transactions.transaction {
            users.insert(outer)
            transactions.requiresNew { users.insert(inner) }
        }

        assertNotNull(users.findById(outer.id))
        assertNotNull(users.findById(inner.id))
    }
}
