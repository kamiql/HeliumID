package dev.kamiql.helium.oauth

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.token.CodeChallengeMethod
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * PKCE is the only thing standing between a public client's authorization code and an attacker
 * who intercepts the redirect. These tests pin the RFC 7636 details that are easy to get
 * subtly wrong.
 */
class PkceTest {

    /** RFC 7636 Appendix B: the specification's own worked example. */
    @Test
    fun `matches the RFC 7636 appendix B test vector`() {
        val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.challengeFor(verifier))
    }

    @Test
    fun `a matching verifier is accepted`() {
        val verifier = "a".repeat(64)
        val challenge = Pkce.challengeFor(verifier)

        assertTrue(Pkce.verify(Secret.of(verifier), challenge, CodeChallengeMethod.S256))
    }

    @Test
    fun `a mismatched verifier is rejected`() {
        val challenge = Pkce.challengeFor("a".repeat(64))

        assertFalse(Pkce.verify(Secret.of("b".repeat(64)), challenge, CodeChallengeMethod.S256))
        // One character different is still a rejection — no prefix matching.
        assertFalse(Pkce.verify(Secret.of("a".repeat(63) + "b"), challenge, CodeChallengeMethod.S256))
    }

    @Test
    fun `verifiers outside the RFC length bounds are rejected`() {
        // 43..128 characters (RFC 7636 §4.1). A short verifier is brute-forceable.
        val tooShort = "a".repeat(42)
        val tooLong = "a".repeat(129)

        assertFalse(Pkce.verify(Secret.of(tooShort), Pkce.challengeFor(tooShort), CodeChallengeMethod.S256))
        assertFalse(Pkce.verify(Secret.of(tooLong), Pkce.challengeFor(tooLong), CodeChallengeMethod.S256))
    }

    @Test
    fun `verifiers containing characters outside the unreserved set are rejected`() {
        val invalid = "a".repeat(42) + "/"
        assertFalse(Pkce.verify(Secret.of(invalid), Pkce.challengeFor(invalid), CodeChallengeMethod.S256))
    }

    @Test
    fun `plain is not an accepted challenge method`() {
        val challenge = "a".repeat(43)

        // Downgrading to `plain` would make PKCE useless against an attacker who can read the
        // authorization request, which is exactly the attacker PKCE exists for.
        assertNull(Pkce.validateChallenge(challenge, "plain"))
        assertNull(Pkce.validateChallenge(challenge, null))
        assertNull(Pkce.validateChallenge(challenge, "S512"))
        assertEquals(CodeChallengeMethod.S256, Pkce.validateChallenge(challenge, "S256"))
    }

    @Test
    fun `a missing or malformed challenge is rejected rather than defaulted`() {
        assertNull(Pkce.validateChallenge(null, "S256"))
        assertNull(Pkce.validateChallenge("", "S256"))
        assertNull(Pkce.validateChallenge("too-short", "S256"))
        assertNull(Pkce.validateChallenge("has spaces in it".repeat(4), "S256"))
    }

    @Test
    fun `the challenge is unpadded base64url`() {
        val challenge = Pkce.challengeFor("z".repeat(43))

        assertFalse(challenge.contains('='), "must be unpadded")
        assertFalse(challenge.contains('+'), "must be url-safe")
        assertFalse(challenge.contains('/'), "must be url-safe")
        // SHA-256 is 32 bytes, which is 43 unpadded base64 characters.
        assertEquals(43, challenge.length)
    }
}
