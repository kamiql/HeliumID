package dev.kamiql.helium.persistence

import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.timestampWithTimeZone
import org.jetbrains.exposed.v1.json.jsonb

/**
 * Exposed table definitions.
 *
 * These mirror `db/migration/V1__baseline.sql` and are **not** the source of truth for the
 * schema: Flyway is. `SchemaUtils.create` is never called, so a drift between the two shows up
 * as a failing integration test rather than as a silently altered production table.
 *
 * Only the explicit DSL is used. No DAO layer, no lazy loading, no implicit joins — CLAUDE.md
 * warns against implicit behaviour in the security core, and an accidental lazy load inside a
 * transaction is exactly that.
 */

/** JSON is stored as an opaque string; the domain never queries inside these documents. */
private fun Table.jsonbText(name: String) = jsonb(name, { it }, { it })

object UsersTable : Table("users") {
    val id = javaUuid("id")
    val username = varchar("username", 64)
    val usernameNormalized = varchar("username_normalized", 64)
    val primaryEmail = varchar("primary_email", 320)
    val primaryEmailNormalized = varchar("primary_email_normalized", 320)
    val firstName = varchar("first_name", 128)
    val lastName = varchar("last_name", 128)
    val status = varchar("status", 40)
    val emailVerifiedAt = timestampWithTimeZone("email_verified_at").nullable()
    val createdAt = timestampWithTimeZone("created_at")
    val updatedAt = timestampWithTimeZone("updated_at")
    val version = long("version")

    override val primaryKey = PrimaryKey(id)
}

object PasswordCredentialsTable : Table("password_credentials") {
    val userId = javaUuid("user_id")
    val passwordHash = text("password_hash")
    val algorithm = varchar("algorithm", 32)
    val parameters = jsonbText("parameters_json")
    val changedAt = timestampWithTimeZone("changed_at")
    val createdAt = timestampWithTimeZone("created_at")

    override val primaryKey = PrimaryKey(userId)
}

object RolesTable : Table("roles") {
    val name = varchar("name", 64)
    val description = text("description")
    val color = varchar("color", 16)
    val builtIn = bool("built_in")
    val createdAt = timestampWithTimeZone("created_at")
    val updatedAt = timestampWithTimeZone("updated_at")

    override val primaryKey = PrimaryKey(name)
}

object RolePermissionsTable : Table("role_permissions") {
    val roleName = varchar("role_name", 64)
    val permission = varchar("permission", 128)

    override val primaryKey = PrimaryKey(roleName, permission)
}

object UserRolesTable : Table("user_roles") {
    val userId = javaUuid("user_id")
    val roleName = varchar("role_name", 64)
    val assignedAt = timestampWithTimeZone("assigned_at")

    override val primaryKey = PrimaryKey(userId, roleName)
}

object ExternalIdentitiesTable : Table("external_identities") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val providerKey = varchar("provider_key", 64)
    val issuer = varchar("issuer", 512)
    val subject = varchar("subject", 512)
    val providerEmail = varchar("provider_email", 320).nullable()
    val profile = jsonbText("profile_json")
    val createdAt = timestampWithTimeZone("created_at")
    val lastLoginAt = timestampWithTimeZone("last_login_at").nullable()

    override val primaryKey = PrimaryKey(id)
}

object MfaFactorsTable : Table("mfa_factors") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val type = varchar("type", 32)
    val label = varchar("label", 64)
    val status = varchar("status", 16)
    val createdAt = timestampWithTimeZone("created_at")
    val lastUsedAt = timestampWithTimeZone("last_used_at").nullable()

    override val primaryKey = PrimaryKey(id)
}

object TotpFactorsTable : Table("totp_factors") {
    val factorId = javaUuid("factor_id")
    val encryptedSecret = text("encrypted_secret")
    val secretKeyVersion = integer("secret_key_version")
    val algorithm = varchar("algorithm", 16)
    val digits = integer("digits")
    val periodSeconds = integer("period_seconds")
    val lastAcceptedStep = long("last_accepted_step").nullable()
    val createdAt = timestampWithTimeZone("created_at")

    override val primaryKey = PrimaryKey(factorId)
}

/**
 * Registered passkeys.
 *
 * `id` **is** the owning `mfa_factors.id` — the same one-row-per-factor shape [TotpFactorsTable]
 * has, which is why the domain calls it `factorId`. V4 adds the foreign key that enforces it.
 *
 * Nothing in this table is secret: the private key never leaves the authenticator, so the stored
 * public key lets a holder of a dump verify signatures, never produce them. That is why these
 * columns are plain `bytea` while the TOTP secret next door is encrypted.
 */
object WebAuthnCredentialsTable : Table("webauthn_credentials") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val credentialId = binary("credential_id")
    val publicKey = binary("public_key")
    val signatureCounter = long("signature_counter")
    val aaguid = javaUuid("aaguid").nullable()
    val transports = varchar("transports", 128)
    val userVerifiedRequired = bool("user_verified_required")
    val backupEligible = bool("backup_eligible")
    val backupState = bool("backup_state")
    val rpId = varchar("rp_id", 255)
    val createdAt = timestampWithTimeZone("created_at")
    val lastUsedAt = timestampWithTimeZone("last_used_at").nullable()

    override val primaryKey = PrimaryKey(id)
}

object RecoveryCodesTable : Table("recovery_codes") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val codeHash = varchar("code_hash", 128)
    val usedAt = timestampWithTimeZone("used_at").nullable()
    val createdAt = timestampWithTimeZone("created_at")

    override val primaryKey = PrimaryKey(id)
}

object VerificationTokensTable : Table("verification_tokens") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val tokenHash = varchar("token_hash", 128)
    val purpose = varchar("purpose", 32)
    val payload = text("payload").nullable()
    val expiresAt = timestampWithTimeZone("expires_at")
    val usedAt = timestampWithTimeZone("used_at").nullable()
    val createdAt = timestampWithTimeZone("created_at")

    override val primaryKey = PrimaryKey(id)
}

object SessionsTable : Table("sessions") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val sessionHash = varchar("session_hash", 128)
    val clientId = varchar("client_id", 128).nullable()
    val createdAt = timestampWithTimeZone("created_at")
    val lastSeenAt = timestampWithTimeZone("last_seen_at")
    val idleExpiresAt = timestampWithTimeZone("idle_expires_at")
    val absoluteExpiresAt = timestampWithTimeZone("absolute_expires_at")
    val revokedAt = timestampWithTimeZone("revoked_at").nullable()
    val authenticatedAt = timestampWithTimeZone("authenticated_at")
    val authenticationMethods = varchar("authentication_methods", 128)
    val ipHash = varchar("ip_hash", 128).nullable()
    val userAgentHash = varchar("user_agent_hash", 128).nullable()
    val deviceLabel = varchar("device_label", 128).nullable()

    override val primaryKey = PrimaryKey(id)
}

object TrustedDevicesTable : Table("trusted_devices") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val tokenHash = varchar("token_hash", 128)
    val previousTokenHash = varchar("previous_token_hash", 128).nullable()
    val label = varchar("label", 128).nullable()
    val createdAt = timestampWithTimeZone("created_at")
    val lastUsedAt = timestampWithTimeZone("last_used_at")
    val expiresAt = timestampWithTimeZone("expires_at")
    val revokedAt = timestampWithTimeZone("revoked_at").nullable()
    val revokedReason = varchar("revoked_reason", 32).nullable()

    override val primaryKey = PrimaryKey(id)
}

object OAuthScopesTable : Table("oauth_scopes") {
    val name = varchar("name", 128)
    val description = text("description")
    val implicit = bool("implicit")

    /** Protocol-level scope the write path refuses to change. See V5__scope_built_in.sql. */
    val builtIn = bool("built_in")
    val createdAt = timestampWithTimeZone("created_at")

    override val primaryKey = PrimaryKey(name)
}

object OAuthClientsTable : Table("oauth_clients") {
    val clientId = varchar("client_id", 128)
    val name = varchar("name", 255)
    val type = varchar("type", 16)
    val secretHash = varchar("secret_hash", 128).nullable()
    val secretRotatedAt = timestampWithTimeZone("secret_rotated_at").nullable()
    val skipConsent = bool("skip_consent")
    val audiences = varchar("audiences", 512)
    val grantTypes = varchar("grant_types", 255)
    val enabled = bool("enabled")
    val createdAt = timestampWithTimeZone("created_at")
    val updatedAt = timestampWithTimeZone("updated_at")

    override val primaryKey = PrimaryKey(clientId)
}

object OAuthRedirectUrisTable : Table("oauth_redirect_uris") {
    val clientId = varchar("client_id", 128)
    val redirectUri = varchar("redirect_uri", 2048)

    override val primaryKey = PrimaryKey(clientId, redirectUri)
}

object OAuthClientScopesTable : Table("oauth_client_scopes") {
    val clientId = varchar("client_id", 128)
    val scope = varchar("scope", 128)

    override val primaryKey = PrimaryKey(clientId, scope)
}

object ConsentsTable : Table("consents") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val clientId = varchar("client_id", 128)
    val grantedScopes = varchar("granted_scopes", 1024)
    val grantedAt = timestampWithTimeZone("granted_at")
    val revokedAt = timestampWithTimeZone("revoked_at").nullable()

    override val primaryKey = PrimaryKey(id)
}

object AuthorizationCodesTable : Table("authorization_codes") {
    val id = javaUuid("id")
    val codeHash = varchar("code_hash", 128)
    val clientId = varchar("client_id", 128)
    val userId = javaUuid("user_id")
    val sessionId = javaUuid("session_id").nullable()
    val redirectUri = varchar("redirect_uri", 2048)
    val scopes = varchar("scopes", 1024)
    val nonce = varchar("nonce", 255).nullable()
    val codeChallenge = varchar("code_challenge", 255)
    val codeChallengeMethod = varchar("code_challenge_method", 16)
    val authenticationMethods = varchar("authentication_methods", 128)
    val authenticatedAt = timestampWithTimeZone("authenticated_at")
    val issuedAt = timestampWithTimeZone("issued_at")
    val expiresAt = timestampWithTimeZone("expires_at")
    val consumedAt = timestampWithTimeZone("consumed_at").nullable()

    override val primaryKey = PrimaryKey(id)
}

object RefreshTokenFamiliesTable : Table("refresh_token_families") {
    val id = javaUuid("id")
    val userId = javaUuid("user_id")
    val clientId = varchar("client_id", 128)
    val sessionId = javaUuid("session_id").nullable()
    val scopes = varchar("scopes", 1024)
    val authenticationMethods = varchar("authentication_methods", 128)
    val createdAt = timestampWithTimeZone("created_at")
    val absoluteExpiresAt = timestampWithTimeZone("absolute_expires_at")
    val revokedAt = timestampWithTimeZone("revoked_at").nullable()
    val reuseDetectedAt = timestampWithTimeZone("reuse_detected_at").nullable()

    override val primaryKey = PrimaryKey(id)
}

object RefreshTokensTable : Table("refresh_tokens") {
    val id = javaUuid("id")
    val familyId = javaUuid("family_id")
    val tokenHash = varchar("token_hash", 128)
    val issuedAt = timestampWithTimeZone("issued_at")
    val expiresAt = timestampWithTimeZone("expires_at")
    val usedAt = timestampWithTimeZone("used_at").nullable()
    val revokedAt = timestampWithTimeZone("revoked_at").nullable()
    val replacedByTokenId = javaUuid("replaced_by_token_id").nullable()

    override val primaryKey = PrimaryKey(id)
}

object RevokedAccessTokensTable : Table("revoked_access_tokens") {
    val tokenId = varchar("token_id", 64)
    val expiresAt = timestampWithTimeZone("expires_at")
    val revokedAt = timestampWithTimeZone("revoked_at")

    override val primaryKey = PrimaryKey(tokenId)
}

object SigningKeysTable : Table("signing_keys") {
    val id = varchar("id", 128)
    val algorithm = varchar("algorithm", 16)
    val publicJwk = text("public_jwk")
    val encryptedPrivateKey = text("encrypted_private_key")
    val status = varchar("status", 16)
    val createdAt = timestampWithTimeZone("created_at")
    val activatedAt = timestampWithTimeZone("activated_at").nullable()
    val retiresAt = timestampWithTimeZone("retires_at").nullable()

    override val primaryKey = PrimaryKey(id)
}

object AuditLogsTable : Table("audit_logs") {
    val id = javaUuid("id")
    val eventType = varchar("event_type", 128)
    val outcome = varchar("outcome", 16)
    val actorUserId = javaUuid("actor_user_id").nullable()
    val subjectUserId = javaUuid("subject_user_id").nullable()
    val clientId = varchar("client_id", 128).nullable()
    val requestId = varchar("request_id", 128)
    val ipHash = varchar("ip_hash", 128).nullable()
    val userAgentHash = varchar("user_agent_hash", 128).nullable()
    val metadata = jsonbText("metadata_json")
    val createdAt = timestampWithTimeZone("created_at")

    override val primaryKey = PrimaryKey(id)
}

object OutboxEventsTable : Table("outbox_events") {
    val id = javaUuid("id")
    val eventType = varchar("event_type", 128)
    val aggregateType = varchar("aggregate_type", 64)
    val aggregateId = varchar("aggregate_id", 128)
    val payload = jsonbText("payload_json")
    val attempts = integer("attempts")
    val availableAt = timestampWithTimeZone("available_at")
    val processedAt = timestampWithTimeZone("processed_at").nullable()
    val lastError = text("last_error").nullable()
    val createdAt = timestampWithTimeZone("created_at")

    override val primaryKey = PrimaryKey(id)
}

object IdempotencyRecordsTable : Table("idempotency_records") {
    val idempotencyKey = varchar("idempotency_key", 255)
    val flowId = varchar("flow_id", 128)
    val clientId = varchar("client_id", 128).nullable()
    val userId = javaUuid("user_id").nullable()
    val requestHash = varchar("request_hash", 128)
    val status = varchar("status", 16)
    val responseHash = varchar("response_hash", 128).nullable()
    val responseBody = text("response_body").nullable()
    val createdAt = timestampWithTimeZone("created_at")
    val completedAt = timestampWithTimeZone("completed_at").nullable()
    val expiresAt = timestampWithTimeZone("expires_at")

    override val primaryKey = PrimaryKey(idempotencyKey, flowId)
}
