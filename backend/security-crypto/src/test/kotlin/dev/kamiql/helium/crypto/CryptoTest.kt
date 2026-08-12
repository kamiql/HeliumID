package dev.kamiql.helium.crypto

import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.credential.PasswordHashParameters
import dev.kamiql.helium.domain.crypto.EncryptedSecret
import kotlinx.coroutines.test.runTest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Deterministic key material so these tests do not depend on the environment. */
private fun testKeyProvider(pepper: String? = null) = LocalKeyProvider.fromBase64(
    dataKeysBase64 = "1:${base64(ByteArray(32) { 1 })},2:${base64(ByteArray(32) { 2 })}",
    currentVersion = 2,
    tokenHmacKeyBase64 = base64(ByteArray(32) { 3 }),
    pepperBase64 = pepper,
    pepperVersion = 1,
)

private fun base64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

/**
 * Argon2id is the control that decides how expensive an offline attack on a leaked database
 * is. These tests keep the cost parameters deliberately tiny so the suite stays fast — they
 * verify behaviour, not tuning.
 */
class Argon2idPasswordHasherTest {

    private val fastParameters = PasswordHashParameters(
        memoryKib = 8 * 1024,
        iterations = 1,
        parallelism = 1,
        saltLength = 16,
        hashLength = 32,
        pepperVersion = 0,
    )

    private fun hasher(
        parameters: PasswordHashParameters = fastParameters,
        pepper: String? = null,
    ) = Argon2idPasswordHasher(
        parameters = parameters,
        random = SecureRandomSource(),
        keyProvider = testKeyProvider(pepper),
        parallelismLimit = 2,
    )

    @Test
    fun `hashes verify and wrong passwords do not`(): Unit = runTest {
        val hasher = hasher()
        val hash = hasher.hash(Secret.of("correct horse battery staple"))

        assertTrue(hasher.verify(Secret.of("correct horse battery staple"), hash))
        assertFalse(hasher.verify(Secret.of("Correct horse battery staple"), hash))
        assertFalse(hasher.verify(Secret.of(""), hash))
    }

    @Test
    fun `the same password hashes differently every time`(): Unit = runTest {
        val hasher = hasher()
        val first = hasher.hash(Secret.of("same password"))
        val second = hasher.hash(Secret.of("same password"))

        // Distinct salts. Without this, identical passwords would be visibly identical in a
        // database dump and a single cracked hash would unlock every account sharing it.
        assertNotEquals(first.encoded, second.encoded)
        assertTrue(hasher.verify(Secret.of("same password"), first))
        assertTrue(hasher.verify(Secret.of("same password"), second))
    }

    @Test
    fun `the encoded hash is self describing and carries no plaintext`(): Unit = runTest {
        val hash = hasher().hash(Secret.of("hunter2"))

        assertTrue(hash.encoded.startsWith("\$argon2id\$v=19\$"))
        assertTrue(hash.encoded.contains("m=8192,t=1,p=1"))
        assertFalse(hash.encoded.contains("hunter2"))
        // Even the wrapper type refuses to print itself.
        assertFalse(hash.toString().contains(hash.encoded))
    }

    @Test
    fun `verification uses the parameters stored with the hash not the current config`(): Unit = runTest {
        val weak = hasher(fastParameters)
        val hash = weak.hash(Secret.of("legacy password"))

        // The deployment later raises the cost. Existing users must still be able to sign in.
        val strong = hasher(fastParameters.copy(memoryKib = 16 * 1024, iterations = 2))
        assertTrue(strong.verify(Secret.of("legacy password"), hash))
        assertTrue(strong.needsRehash(hash), "the old hash should be flagged for upgrade")
        assertFalse(weak.needsRehash(hash))
    }

    @Test
    fun `a pepper changes the derived hash`(): Unit = runTest {
        val withoutPepper = hasher()
        val withPepper = hasher(pepper = base64(ByteArray(32) { 9 }))

        val hash = withPepper.hash(Secret.of("same password"))
        // Without the pepper — which lives in the KMS, not the database — the hash cannot be
        // verified. That is the whole point: a database-only leak is not enough to attack it.
        assertFalse(withoutPepper.verify(Secret.of("same password"), hash))
        assertTrue(withPepper.verify(Secret.of("same password"), hash))
    }

    @Test
    fun `dummy verification always fails but still does the work`(): Unit = runTest {
        val hasher = hasher()
        assertFalse(hasher.verifyDummy(Secret.of("anything")))
    }

    @Test
    fun `a corrupt stored hash fails verification instead of throwing`(): Unit = runTest {
        val hasher = hasher()
        val valid = hasher.hash(Secret.of("password"))
        val corrupt = valid.copy(encoded = "not-a-valid-phc-string")

        // A malformed row must not take the login endpoint down with an exception.
        assertFalse(hasher.verify(Secret.of("password"), corrupt))
    }
}

class TokenHasherTest {

    private val hasher = HmacTokenHasher(testKeyProvider())

    @Test
    fun `hashing is deterministic so it can be used as a lookup key`() {
        assertEquals(hasher.hash("token-value"), hasher.hash("token-value"))
        assertNotEquals(hasher.hash("token-value"), hasher.hash("other-value"))
    }

    @Test
    fun `the hash does not contain the token`() {
        val hash = hasher.hash("super-secret-refresh-token")
        assertFalse(hash.contains("super-secret"))
    }

    @Test
    fun `matches compares correctly`() {
        val hash = hasher.hash("token")
        assertTrue(hasher.matches("token", hash))
        assertFalse(hasher.matches("token ", hash))
    }

    @Test
    fun `a different key produces a different hash`() {
        val other = HmacTokenHasher(
            LocalKeyProvider.fromBase64(
                dataKeysBase64 = "1:${base64(ByteArray(32) { 1 })}",
                currentVersion = 1,
                tokenHmacKeyBase64 = base64(ByteArray(32) { 42 }),
            ),
        )
        // Rotating the HMAC key invalidates every stored token hash at once — documented as a
        // break-glass action, and this test is what proves it really does.
        assertNotEquals(hasher.hash("token"), other.hash("token"))
    }
}

class SecretCipherTest {

    private val cipher = AesGcmSecretCipher(testKeyProvider(), SecureRandomSource())

    @Test
    fun `round trips`() {
        val plaintext = "JBSWY3DPEHPK3PXP".toByteArray()
        val encrypted = cipher.encrypt(plaintext)

        assertContentEqualsHelper(plaintext, cipher.decrypt(encrypted))
    }

    @Test
    fun `encrypting twice produces different ciphertext`() {
        val plaintext = "same secret".toByteArray()
        val first = cipher.encrypt(plaintext)
        val second = cipher.encrypt(plaintext)

        // Fresh nonce each time; GCM with a reused nonce leaks the plaintext XOR.
        assertFalse(first.ciphertext.contentEquals(second.ciphertext))
        assertFalse(first.nonce.contentEquals(second.nonce))
    }

    @Test
    fun `tampered ciphertext is rejected rather than silently decrypted`() {
        val encrypted = cipher.encrypt("sensitive".toByteArray())
        val tampered = EncryptedSecret(
            ciphertext = encrypted.ciphertext.copyOf().also { it[0] = (it[0] + 1).toByte() },
            nonce = encrypted.nonce,
            keyVersion = encrypted.keyVersion,
        )

        // Authenticated encryption: fail closed, never return a wrong-but-plausible plaintext.
        assertFailsWith<IllegalStateException> { cipher.decrypt(tampered) }
    }

    @Test
    fun `ciphertext cannot be replayed under a different key version`() {
        val encrypted = cipher.encrypt("sensitive".toByteArray())
        val relabelled = EncryptedSecret(encrypted.ciphertext, encrypted.nonce, keyVersion = 1)

        // The version is authenticated additional data, so relabelling breaks the tag.
        assertFailsWith<IllegalStateException> { cipher.decrypt(relabelled) }
    }

    @Test
    fun `an old key version can still be decrypted after rotation`() {
        val provider = testKeyProvider()
        val old = AesGcmSecretCipher(
            object : dev.kamiql.helium.domain.crypto.KeyProvider by provider {
                override val currentDataKeyVersion: Int = 1
            },
            SecureRandomSource(),
        )
        val encrypted = old.encrypt("legacy totp secret".toByteArray())
        assertEquals(1, encrypted.keyVersion)

        // The current cipher writes v2 but must still read v1 (concept §7.2).
        assertContentEqualsHelper("legacy totp secret".toByteArray(), cipher.decrypt(encrypted))
    }

    @Test
    fun `the storage encoding round trips and redacts in toString`() {
        val encrypted = cipher.encrypt("value".toByteArray())
        val encoded = encrypted.encode()

        assertTrue(encoded.startsWith("v2."))
        assertFalse(encrypted.toString().contains(encoded))

        val decoded = assertNotNull(EncryptedSecret.decode(encoded))
        assertContentEqualsHelper("value".toByteArray(), cipher.decrypt(decoded))
        assertNull(EncryptedSecret.decode("garbage"))
    }
}

class RandomSourceTest {

    private val random = SecureRandomSource()

    @Test
    fun `tokens are url safe and unique`() {
        val tokens = List(200) { random.token(32) }
        assertEquals(200, tokens.toSet().size)
        assertTrue(tokens.all { token -> token.all { it.isLetterOrDigit() || it == '-' || it == '_' } })
    }

    @Test
    fun `recovery codes avoid ambiguous characters`() {
        val codes = List(200) { random.humanCode() }
        // 0/O and 1/I/L are the classic transcription errors on a printed recovery sheet.
        assertTrue(codes.none { it.contains('0') || it.contains('O') })
        assertTrue(codes.none { it.contains('1') || it.contains('I') || it.contains('L') })
        assertTrue(codes.all { it.matches(Regex("^[A-Z2-9]{5}-[A-Z2-9]{5}$")) })
    }
}

private fun assertContentEqualsHelper(expected: ByteArray, actual: ByteArray) {
    assertTrue(expected.contentEquals(actual), "byte arrays differ")
}
