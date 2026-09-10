package dev.kamiql.helium.identity

import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.mfa.MfaPolicy
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.flow.FlowResult
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * `MfaPolicy.REQUIRED_FOR_PRIVILEGED` turns on a gate that can lock the whole system out, so the
 * question these tests ask is not "does the gate work" but "does it close on the right accounts".
 *
 * It once closed on all of them. The login flow read account privilege out of
 * [Permission.STEP_UP_REQUIRED], which names sensitive *operations* and therefore includes
 * `account:password:change` and three of its neighbours — permissions the built-in `USER` role
 * grants to everyone. Every account was privileged, every account without a factor was refused,
 * and enrolling a factor needs a session you can no longer obtain. A production deployment
 * deadlocked on exactly this.
 *
 * The suite escaped it because its fixtures were unrepresentative: the flow tests granted a
 * single hand-picked permission (`account:session:manage`, the one self-service entry *not* in
 * `STEP_UP_REQUIRED`), and the end-to-end app runs under `MfaPolicy.OPTIONAL`. So these tests are
 * written against [Role.BUILT_IN] rather than against a permission chosen here — if the seeded
 * roles and the privilege predicate ever drift apart again, this is where it surfaces.
 */
class MfaPolicyTest {

    private companion object {
        const val ALICE = "alice"
        const val ADMIN = "admin"

        val USER_PERMISSIONS: Set<Permission> =
            Role.BUILT_IN.first { it.name == Role.USER }.permissions

        val ADMINISTRATOR_PERMISSIONS: Set<Permission> =
            Role.BUILT_IN.first { it.name == Role.ADMINISTRATOR }.permissions
    }

    // =========================================================================
    // the invariant the seeded roles must satisfy
    // =========================================================================

    @Test
    fun `the built-in USER role does not make an account privileged`() {
        assertTrue(
            USER_PERMISSIONS.none { it in Permission.PRIVILEGED_ACCOUNT },
            "the default role every account receives must not count as privileged, or " +
                "REQUIRED_FOR_PRIVILEGED locks out the entire system",
        )
    }

    @Test
    fun `the built-in ADMINISTRATOR role makes an account privileged`() {
        assertTrue(ADMINISTRATOR_PERMISSIONS.any { it in Permission.PRIVILEGED_ACCOUNT })
    }

    // =========================================================================
    // what the gate does to a real account
    // =========================================================================

    @Test
    fun `an ordinary account signs in without a factor under required-for-privileged`(): Unit = runTest {
        val fixture = TrustedDeviceFixture(mfaPolicy = MfaPolicy.REQUIRED_FOR_PRIVILEGED)
        val id = fixture.createUser(ALICE, mfaEnrolled = false)
        fixture.roles.grant(id, USER_PERMISSIONS)

        val result = fixture.login(ALICE)

        assertIs<FlowResult.Success<LoginSucceeded>>(
            result,
            "a plain user has nothing the policy is meant to protect and must not be gated",
        )
    }

    @Test
    fun `an administrator without a factor is refused under required-for-privileged`(): Unit = runTest {
        val fixture = TrustedDeviceFixture(mfaPolicy = MfaPolicy.REQUIRED_FOR_PRIVILEGED)
        val id = fixture.createUser(ADMIN, mfaEnrolled = false)
        fixture.roles.grant(id, ADMINISTRATOR_PERMISSIONS)

        val result = fixture.login(ADMIN)

        val failure = assertIs<FlowResult.Failure>(result)
        assertEquals(AuthError.Forbidden("mfa:enrollment-required"), failure.error)
    }

    @Test
    fun `an administrator with a factor is challenged rather than refused`(): Unit = runTest {
        val fixture = TrustedDeviceFixture(mfaPolicy = MfaPolicy.REQUIRED_FOR_PRIVILEGED)
        val id = fixture.createUser(ADMIN, mfaEnrolled = true)
        fixture.roles.grant(id, ADMINISTRATOR_PERMISSIONS)

        val result = fixture.login(ADMIN)

        assertIs<FlowResult.Challenge>(result)
    }
}
