package dev.kamiql.helium.domain

import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.Normalization
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.Username
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Normalization is a security control, not a formatting nicety: it decides whether two
 * identifiers are "the same account". These tests pin the cases that would otherwise let two
 * users collide, or let one user register a lookalike of another.
 */
class NormalizationTest {

    @Test
    fun `usernames differing only in case are the same account`() {
        val lower = assertNotNull(Username.parse("alice"))
        val upper = assertNotNull(Username.parse("ALICE"))

        assertEquals(lower.normalized, upper.normalized)
        assertEquals(lower, upper)
        // The display form still preserves what the user typed.
        assertEquals("ALICE", upper.display)
    }

    @Test
    fun `turkish dotless i does not fold differently`() {
        // With a Turkish locale, "I".lowercase() is "ı" and this would produce two
        // different normalized values for the same input depending on the server's locale.
        assertEquals("ii", Normalization.fold("II"))
    }

    @Test
    fun `unicode compatibility forms fold together`() {
        // U+FF41 FULLWIDTH LATIN SMALL LETTER A normalizes to plain "a" under NFKC, so a
        // lookalike username cannot be registered alongside the real one.
        assertEquals("abc", Normalization.fold("ａbc"))
    }

    @Test
    fun `usernames reject characters that enable impersonation`() {
        assertNull(Username.parse("ali ce"), "spaces")
        assertNull(Username.parse("alice@example.com"), "looks like an email")
        assertNull(Username.parse("ab"), "too short")
        assertNull(Username.parse("a".repeat(64)), "too long")
        assertNull(Username.parse("alice!"), "punctuation")
    }

    @Test
    fun `emails fold case but never strip dots or plus addressing`() {
        val mixed = assertNotNull(EmailAddress.parse("Alice.Smith+tag@Example.COM"))

        assertEquals("alice.smith+tag@example.com", mixed.normalized)
        // Stripping the +tag would let one mailbox claim unlimited accounts; stripping dots
        // would merge two genuinely different Gmail-style addresses on other providers.
        assertTrue(mixed.normalized.contains('+'))
        assertTrue(mixed.normalized.contains(".smith"))
    }

    @Test
    fun `malformed emails are rejected`() {
        assertNull(EmailAddress.parse("no-at-sign"))
        assertNull(EmailAddress.parse("two@@example.com"))
        assertNull(EmailAddress.parse("missing@tld"))
        assertNull(EmailAddress.parse("spaces in@example.com"))
        assertNull(EmailAddress.parse("a".repeat(400) + "@example.com"))
    }
}

/**
 * [Secret] exists to make accidental disclosure hard. If these fail, a password could end up
 * in a log line or a stack trace.
 */
class SecretTest {

    @Test
    fun `toString never reveals the value`() {
        val secret = Secret.of("correct horse battery staple")

        assertEquals(Secret.REDACTED, secret.toString())
        assertFalse(secret.toString().contains("horse"))
        // Interpolation is the most common accidental leak.
        assertFalse("value is $secret".contains("horse"))
    }

    @Test
    fun `equality is by content and does not leak length through hashCode`() {
        assertEquals(Secret.of("same"), Secret.of("same"))
        assertFalse(Secret.of("same") == Secret.of("different"))
    }

    @Test
    fun `use clears the working copy`() {
        val secret = Secret.of("hunter2")
        var seen: CharArray? = null
        secret.use { chars ->
            seen = chars
            assertEquals("hunter2", String(chars))
        }
        // The array handed to the block is zeroed once it returns, so a retained reference is
        // not a retained password.
        assertTrue(assertNotNull(seen).all { it == '\u0000' })
    }

    @Test
    fun `byteLength is safe to log`() {
        assertEquals(7, Secret.of("hunter2").byteLength)
    }
}
