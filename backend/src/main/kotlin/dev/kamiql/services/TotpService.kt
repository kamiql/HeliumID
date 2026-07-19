package dev.kamiql.services

import dev.samstevens.totp.code.DefaultCodeGenerator
import dev.samstevens.totp.code.DefaultCodeVerifier
import dev.samstevens.totp.qr.QrData
import dev.samstevens.totp.qr.ZxingPngQrGenerator
import dev.samstevens.totp.secret.DefaultSecretGenerator
import dev.samstevens.totp.time.SystemTimeProvider
import io.ktor.util.encodeBase64

object TotpService {
    private val secretGenerator = DefaultSecretGenerator()
    private val verifier = DefaultCodeVerifier(
        DefaultCodeGenerator(),
        SystemTimeProvider()
    )
    private val qrGenerator = ZxingPngQrGenerator()

    fun generateSecret(): String {
        return secretGenerator.generate()
    }

    fun verify(
        secret: String,
        code: String
    ): Boolean {
        return verifier.isValidCode(secret, code)
    }

    fun generateQrCode(
        secret: String,
        label: String,
        issuer: String = "HeliumID"
    ): String {
        val data = QrData.Builder()
            .label(label)
            .secret(secret)
            .issuer(issuer)
            .build()

        return "data:image/png;base64,${qrGenerator.generate(data).encodeBase64()}"
    }
}