package dev.kamiql.helium.demo

import dev.kamiql.helium.demo.auth.SessionStore
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The login transaction: the server-side half of `state`, `nonce` and the PKCE verifier.
 *
 * All three have to survive the round trip to HeliumID and back without the browser being
 * trusted to carry them. What the browser gets is an opaque handle, and these tests pin the two
 * properties that make it safe — single use, and bounded lifetime.
 */
class LoginTransactionTest {

    private var now: Instant = Instant.parse("2026-08-13T10:00:00Z")
    private val store = SessionStore { now }

    @Test
    fun `each login gets fresh values`() {
        val (firstHandle, first) = store.beginLogin("/")
        val (secondHandle, second) = store.beginLogin("/")

        assertNotEquals(firstHandle, secondHandle)
        assertNotEquals(first.state, second.state)
        assertNotEquals(first.nonce, second.nonce)
        assertNotEquals(first.codeVerifier, second.codeVerifier)
    }

    /** The handle is not the state: the browser never holds the value being verified. */
    @Test
    fun `the handle differs from the state it looks up`() {
        val (handle, transaction) = store.beginLogin("/")

        assertNotEquals(handle, transaction.state)
    }

    /**
     * Single use. This is what stops an authorization response from being replayed — a captured
     * callback URL, opened a second time, finds nothing to match against.
     */
    @Test
    fun `a transaction is consumed exactly once`() {
        val (handle, transaction) = store.beginLogin("/documents/1")

        val first = assertNotNull(store.consumeLogin(handle))
        assertEquals(transaction.state, first.state)
        assertEquals("/documents/1", first.returnTo)

        assertNull(store.consumeLogin(handle), "a second callback must find nothing")
    }

    @Test
    fun `an unknown handle resolves to nothing`() {
        store.beginLogin("/")

        assertNull(store.consumeLogin("not-a-handle"))
        assertNull(store.consumeLogin(null))
    }

    @Test
    fun `an abandoned login expires`() {
        val (handle, _) = store.beginLogin("/")

        now = now.plus(Duration.ofMinutes(11))

        assertNull(store.consumeLogin(handle), "a stale transaction must not be usable")
    }

    @Test
    fun `a login still inside the window is usable`() {
        val (handle, _) = store.beginLogin("/")

        now = now.plus(Duration.ofMinutes(9))

        assertNotNull(store.consumeLogin(handle))
    }
}
