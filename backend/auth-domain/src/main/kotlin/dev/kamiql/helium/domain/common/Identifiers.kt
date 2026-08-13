package dev.kamiql.helium.domain.common

import java.util.UUID

/**
 * Identifiers are value classes so that a [UserId] can never be passed where a [SessionId]
 * is expected. CLAUDE.md: "Make invalid states unrepresentable where practical with sealed
 * interfaces and value classes."
 */
@JvmInline
value class UserId(val value: UUID) {
    override fun toString(): String = value.toString()

    companion object {
        fun random(): UserId = UserId(UUID.randomUUID())
        fun parse(raw: String): UserId? = raw.toUuidOrNull()?.let(::UserId)
    }
}

@JvmInline
value class SessionId(val value: UUID) {
    override fun toString(): String = value.toString()

    companion object {
        fun random(): SessionId = SessionId(UUID.randomUUID())
        fun parse(raw: String): SessionId? = raw.toUuidOrNull()?.let(::SessionId)
    }
}

@JvmInline
value class CredentialId(val value: UUID) {
    companion object {
        fun random(): CredentialId = CredentialId(UUID.randomUUID())
    }
}

@JvmInline
value class ExternalIdentityId(val value: UUID) {
    companion object {
        fun random(): ExternalIdentityId = ExternalIdentityId(UUID.randomUUID())
    }
}

@JvmInline
value class MfaFactorId(val value: UUID) {
    override fun toString(): String = value.toString()

    companion object {
        fun random(): MfaFactorId = MfaFactorId(UUID.randomUUID())
        fun parse(raw: String): MfaFactorId? = raw.toUuidOrNull()?.let(::MfaFactorId)
    }
}

@JvmInline
value class RecoveryCodeId(val value: UUID) {
    companion object {
        fun random(): RecoveryCodeId = RecoveryCodeId(UUID.randomUUID())
    }
}

@JvmInline
value class TrustedDeviceId(val value: UUID) {
    override fun toString(): String = value.toString()

    companion object {
        fun random(): TrustedDeviceId = TrustedDeviceId(UUID.randomUUID())
        fun parse(raw: String): TrustedDeviceId? = raw.toUuidOrNull()?.let(::TrustedDeviceId)
    }
}

@JvmInline
value class RefreshTokenFamilyId(val value: UUID) {
    companion object {
        fun random(): RefreshTokenFamilyId = RefreshTokenFamilyId(UUID.randomUUID())
    }
}

@JvmInline
value class RefreshTokenId(val value: UUID) {
    companion object {
        fun random(): RefreshTokenId = RefreshTokenId(UUID.randomUUID())
    }
}

@JvmInline
value class AuthorizationCodeId(val value: UUID) {
    companion object {
        fun random(): AuthorizationCodeId = AuthorizationCodeId(UUID.randomUUID())
    }
}

@JvmInline
value class ConsentId(val value: UUID) {
    companion object {
        fun random(): ConsentId = ConsentId(UUID.randomUUID())
    }
}

@JvmInline
value class AuditEventId(val value: UUID) {
    companion object {
        fun random(): AuditEventId = AuditEventId(UUID.randomUUID())
    }
}

@JvmInline
value class OutboxEventId(val value: UUID) {
    companion object {
        fun random(): OutboxEventId = OutboxEventId(UUID.randomUUID())
    }
}

@JvmInline
value class VerificationTokenId(val value: UUID) {
    companion object {
        fun random(): VerificationTokenId = VerificationTokenId(UUID.randomUUID())
    }
}

@JvmInline
value class SigningKeyId(val value: String) {
    /** Published as the JOSE `kid` header, e.g. `auth-signing-key-2026-08`. */
    override fun toString(): String = value
}

/**
 * OAuth client identifier. Public value: it appears in redirect URLs and logs, so it must
 * never encode a secret.
 */
@JvmInline
value class ClientId(val value: String) {
    override fun toString(): String = value

    init {
        require(value.isNotBlank()) { "client id must not be blank" }
    }
}

/** Correlates every log line, audit row and problem response for a single inbound request. */
@JvmInline
value class RequestId(val value: String) {
    override fun toString(): String = value
}

/**
 * Opaque handle for a short-lived, single-use security transaction (MFA challenge, provider
 * linking, consent). Returned to clients; the underlying secret state stays server side.
 */
@JvmInline
value class TransactionId(val value: String) {
    override fun toString(): String = value
}

internal fun String.toUuidOrNull(): UUID? =
    try {
        UUID.fromString(this)
    } catch (_: IllegalArgumentException) {
        null
    }
