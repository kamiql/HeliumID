package dev.kamiql.helium.oauth

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.RegisteredClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.TokenHasher
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.policy.Permission
import dev.kamiql.helium.domain.policy.userIdOrNull
import dev.kamiql.helium.domain.repository.ClientRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowStateKey
import dev.kamiql.helium.flow.StepResult
import dev.kamiql.helium.flow.TransactionPolicy
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.requirement.Authenticated
import dev.kamiql.helium.flow.requirement.ReauthenticatedWithin
import dev.kamiql.helium.flow.step
import java.net.URI

/**
 * The OpenID Provider metadata document served at
 * `/.well-known/openid-configuration`.
 *
 * Everything advertised here must actually work: clients configure themselves from it, and
 * advertising a capability the server does not have produces failures that look like client
 * bugs. Note the absences — no `password` grant, no `implicit`, no `plain` PKCE.
 */
data class DiscoveryMetadata(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val userinfoEndpoint: String,
    val jwksUri: String,
    val revocationEndpoint: String,
    val introspectionEndpoint: String,
    /**
     * RP-initiated logout, advertised only if it exists — which today it does not.
     *
     * This used to be published unconditionally as `{issuer}/oauth2/logout`, a path with no route
     * behind it, so every relying party that read discovery and honoured it was pointed at a 404.
     * An absent optional field is a correct discovery document (OIDC Discovery §3 makes this
     * `OPTIONAL`); a present one naming a dead endpoint is not.
     *
     * Implementing it properly means `id_token_hint` validation, a per-client
     * `post_logout_redirect_uri` allowlist and a migration to store it — a feature, not a repair,
     * and tracked separately.
     */
    val endSessionEndpoint: String? = null,
    val scopesSupported: List<String>,
    val responseTypesSupported: List<String> = listOf("code"),
    val grantTypesSupported: List<String> = listOf("authorization_code", "refresh_token", "client_credentials"),
    val subjectTypesSupported: List<String> = listOf("public"),
    val idTokenSigningAlgValuesSupported: List<String> = listOf("ES256"),
    val tokenEndpointAuthMethodsSupported: List<String> = listOf("client_secret_post", "client_secret_basic", "none"),
    val codeChallengeMethodsSupported: List<String> = listOf("S256"),
    val claimsSupported: List<String> = listOf(
        "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "acr",
        "name", "preferred_username", "given_name", "family_name", "email", "email_verified",
    ),
) {
    companion object {
        fun forIssuer(issuer: String, scopes: List<String>): DiscoveryMetadata {
            val base = issuer.trimEnd('/')
            return DiscoveryMetadata(
                issuer = base,
                authorizationEndpoint = "$base/oauth2/authorize",
                tokenEndpoint = "$base/oauth2/token",
                userinfoEndpoint = "$base/userinfo",
                jwksUri = "$base/.well-known/jwks.json",
                revocationEndpoint = "$base/oauth2/revoke",
                introspectionEndpoint = "$base/oauth2/introspect",
                scopesSupported = scopes,
            )
        }
    }
}

/**
 * Client registration and lifecycle.
 *
 * Administrative rather than dynamic (RFC 7591 is not implemented): a self-service endpoint
 * that lets anyone register redirect URIs on a production authorization server is a liability
 * unless it is itself tightly authorized, and this deployment has an admin UI instead.
 */
class ClientAdminFlows(
    private val clients: ClientRepository,
    private val users: UserRepository,
    private val sessions: SessionRepository,
    private val tokenHasher: TokenHasher,
    private val random: RandomSource,
    private val allowInsecureRedirects: Boolean,
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
) {

    private val registeredKey = FlowStateKey<RegisteredClient>("registered_client", sensitive = true)
    private val secretKey = FlowStateKey<ClientSecretIssued>("client_secret", sensitive = true)
    private val clientIdKey = FlowStateKey<ClientId>("client_id")
    private val scopeKey = FlowStateKey<Scope>("scope")

    val register: Flow<RegisterClientCommand, ClientSecretIssued> =
        flow(FlowId("admin.client.register")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_CLIENT_WRITE)

            step(
                step("register") { command, context, state ->
                    validateClientId(command.clientId)?.let { return@step StepResult.Fail(it) }
                    if (clients.findById(ClientId(command.clientId)) != null) {
                        return@step StepResult.Fail(AuthError.Conflict)
                    }
                    validateRedirectUris(command.redirectUris)?.let { return@step StepResult.Fail(it) }

                    val known = clients.listScopes().map { it.name }.toSet()
                    val unknown = command.scopes - known
                    if (unknown.isNotEmpty()) {
                        return@step StepResult.Fail(AuthError.InvalidScope(unknown))
                    }
                    if (command.type == ClientType.PUBLIC &&
                        GrantType.CLIENT_CREDENTIALS in command.grantTypes
                    ) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("grant_types" to "client_credentials_requires_secret")),
                        )
                    }

                    // Only confidential clients get a secret; a "secret" shipped inside a SPA
                    // bundle is not a secret, and the schema constraint enforces this too.
                    val plaintextSecret = if (command.type == ClientType.CONFIDENTIAL) random.token(32) else null

                    val client = OAuthClient(
                        clientId = ClientId(command.clientId),
                        name = command.name,
                        type = command.type,
                        secretHash = plaintextSecret?.let(tokenHasher::hash),
                        secretRotatedAt = plaintextSecret?.let { context.now },
                        redirectUris = command.redirectUris,
                        allowedScopes = command.scopes,
                        allowedGrantTypes = command.grantTypes,
                        skipConsent = command.skipConsent,
                        audiences = command.audiences.ifEmpty { setOf(command.clientId) },
                        enabled = true,
                        createdAt = context.now,
                        updatedAt = context.now,
                    )
                    clients.insert(client)

                    state[clientIdKey] = client.clientId
                    state[secretKey] = ClientSecretIssued(client.clientId, plaintextSecret, context.now)
                    StepResult.Continue
                },
            )

            effect(
                effect("client-registered") { _, context, state ->
                    listOf(DomainEvent.ClientRegistered(state.require(clientIdKey), context.actor.userIdOrNull))
                },
            )

            result { state -> state.require(secretKey) }
        }

    val update: Flow<UpdateClientCommand, Unit> =
        flow(FlowId("admin.client.update")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_CLIENT_WRITE)

            step(
                step("update") { command, context, _ ->
                    val existing = clients.findById(command.clientId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)

                    command.redirectUris?.let { uris ->
                        validateRedirectUris(uris)?.let { return@step StepResult.Fail(it) }
                    }
                    command.scopes?.let { scopes ->
                        val known = clients.listScopes().map { it.name }.toSet()
                        val unknown = scopes - known
                        if (unknown.isNotEmpty()) return@step StepResult.Fail(AuthError.InvalidScope(unknown))
                    }

                    clients.update(
                        existing.copy(
                            name = command.name ?: existing.name,
                            redirectUris = command.redirectUris ?: existing.redirectUris,
                            allowedScopes = command.scopes ?: existing.allowedScopes,
                            allowedGrantTypes = command.grantTypes ?: existing.allowedGrantTypes,
                            audiences = command.audiences ?: existing.audiences,
                            skipConsent = command.skipConsent ?: existing.skipConsent,
                            enabled = command.enabled ?: existing.enabled,
                            updatedAt = context.now,
                        ),
                    )
                    StepResult.Continue
                },
            )

            result { }
        }

    /**
     * Issues a new secret.
     *
     * The old secret stops working immediately. Overlapping secrets would make rotation
     * painless, but they also mean a leaked secret stays valid after the operator believes it
     * has been rotated — the wrong trade for a security control.
     */
    val rotateSecret: Flow<RotateClientSecretCommand, ClientSecretIssued> =
        flow(FlowId("admin.client.rotate-secret")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_CLIENT_WRITE)

            step(
                step("rotate") { command, context, state ->
                    val client = clients.findById(command.clientId)
                        ?: return@step StepResult.Fail(AuthError.NotFound)
                    if (client.type != ClientType.CONFIDENTIAL) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("type" to "public_clients_have_no_secret")),
                        )
                    }

                    val plaintext = random.token(32)
                    clients.updateSecret(command.clientId, tokenHasher.hash(plaintext), context.now)
                    state[clientIdKey] = command.clientId
                    state[secretKey] = ClientSecretIssued(command.clientId, plaintext, context.now)
                    StepResult.Continue
                },
            )

            effect(
                effect("secret-rotated") { _, context, state ->
                    listOf(DomainEvent.ClientSecretRotated(state.require(clientIdKey), context.actor.userIdOrNull))
                },
            )

            result { state -> state.require(secretKey) }
        }

    val delete: Flow<DeleteClientCommand, Unit> =
        flow(FlowId("admin.client.delete")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_CLIENT_WRITE)

            step(
                step("delete") { command, _, _ ->
                    if (!clients.delete(command.clientId)) StepResult.Fail(AuthError.NotFound)
                    else StepResult.Continue
                },
            )

            result { }
        }

    /**
     * Creates a scope or edits its consent-screen text.
     *
     * Same requirement profile as the client flows above, and deliberately the same permission:
     * a scope is one half of the contract a client is registered against, and an administrator
     * who may define clients is already the person who defines what clients may ask for. A
     * separate `admin:scope:write` would leave every existing ADMINISTRATOR role quietly
     * incomplete after this deployment.
     */
    val upsertScope: Flow<UpsertScopeCommand, Scope> =
        flow(FlowId("admin.scope.upsert")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_CLIENT_WRITE)

            step(
                step("upsert") { command, context, state ->
                    if (!Scope.NAME_PATTERN.matches(command.name)) {
                        return@step StepResult.Fail(AuthError.ValidationFailed(mapOf("name" to "invalid")))
                    }
                    if (command.description.isBlank() || command.description.length > 200) {
                        return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("description" to "invalid")),
                        )
                    }
                    // Built-ins are protocol, not policy. Editing `openid`'s description would
                    // reword the one scope users cannot decline, and marking it non-implicit
                    // would put it on the consent screen as a refusable choice it is not.
                    if (clients.findScope(command.name)?.builtIn == true) {
                        return@step StepResult.Fail(AuthError.Conflict)
                    }

                    val saved = clients.upsertScope(
                        Scope(
                            name = command.name,
                            description = command.description,
                            implicit = command.implicit,
                            builtIn = false,
                        ),
                        context.now,
                    )
                    state[scopeKey] = saved
                    StepResult.Continue
                },
            )

            effect(
                effect("scope-upserted") { command, context, _ ->
                    listOf(DomainEvent.ScopeUpserted(command.name, context.actor.userIdOrNull))
                },
            )

            result { state -> state.require(scopeKey) }
        }

    /**
     * Removes a scope from the catalogue.
     *
     * Refuses while any client still lists it. `oauth_client_scopes.scope` cascades, so an
     * unguarded delete would strip the scope from those clients without a word and surface much
     * later as `invalid_scope` on an authorization request that used to work. Detach it from the
     * clients first — that way the decision is visible per client.
     */
    val deleteScope: Flow<DeleteScopeCommand, Unit> =
        flow(FlowId("admin.scope.delete")) {
            transaction(TransactionPolicy.Required)
            require(Authenticated)
            require(ReauthenticatedWithin(lifetimes.reauthenticationWindow, sessions))
            requirePermission(Permission.ADMIN_CLIENT_WRITE)

            step(
                step("delete") { command, _, _ ->
                    val existing = clients.findScope(command.name)
                        ?: return@step StepResult.Fail(AuthError.NotFound)
                    if (existing.builtIn) return@step StepResult.Fail(AuthError.Conflict)
                    if (clients.clientsUsingScope(command.name) > 0) {
                        return@step StepResult.Fail(AuthError.Conflict)
                    }

                    if (!clients.deleteScope(command.name)) StepResult.Fail(AuthError.NotFound)
                    else StepResult.Continue
                },
            )

            effect(
                effect("scope-deleted") { command, context, _ ->
                    listOf(DomainEvent.ScopeDeleted(command.name, context.actor.userIdOrNull))
                },
            )

            result { }
        }

    private fun validateClientId(value: String): AuthError? {
        val shape = Regex("^[a-z0-9][a-z0-9._-]{2,63}$")
        return if (shape.matches(value)) null
        else AuthError.ValidationFailed(mapOf("client_id" to "invalid"))
    }

    /**
     * Rejects redirect URIs that would weaken the authorization code flow.
     *
     * Wildcards, fragments and open-ended paths are all refused; HTTP is refused outside local
     * development, where `allowInsecureRedirects` opens it for `localhost` only.
     */
    private fun validateRedirectUris(uris: Set<String>): AuthError? {
        if (uris.isEmpty()) return AuthError.ValidationFailed(mapOf("redirect_uris" to "required"))

        uris.forEach { raw ->
            val uri = runCatching { URI(raw) }.getOrNull()
                ?: return AuthError.ValidationFailed(mapOf("redirect_uris" to "malformed"))

            if (uri.fragment != null) {
                // RFC 6749 §3.1.2: the endpoint URI must not include a fragment.
                return AuthError.ValidationFailed(mapOf("redirect_uris" to "fragment_not_allowed"))
            }
            if ('*' in raw) {
                return AuthError.ValidationFailed(mapOf("redirect_uris" to "wildcards_not_allowed"))
            }

            val scheme = uri.scheme?.lowercase()
            val host = uri.host?.lowercase()
            val loopback = host == "localhost" || host == "127.0.0.1" || host == "::1"

            when {
                scheme == "https" -> Unit
                // Native apps legitimately use a custom scheme for their callback.
                scheme != null && scheme !in setOf("http", "https") && uri.isAbsolute -> Unit
                scheme == "http" && loopback && allowInsecureRedirects -> Unit
                else -> return AuthError.ValidationFailed(mapOf("redirect_uris" to "https_required"))
            }
        }
        return null
    }
}

/**
 * Builds the `/userinfo` response.
 *
 * Claims are gated on the granted scopes — a token without the `email` scope must not be able
 * to read the address here, or the scope system means nothing.
 */
fun buildUserInfo(user: dev.kamiql.helium.domain.user.User, scopes: Set<String>): UserInfoResponse =
    UserInfoResponse(
        sub = user.id.value.toString(),
        name = if (Scope.PROFILE in scopes) user.displayName else null,
        preferredUsername = if (Scope.PROFILE in scopes) user.username.display else null,
        givenName = if (Scope.PROFILE in scopes) user.firstName else null,
        familyName = if (Scope.PROFILE in scopes) user.lastName else null,
        email = if (Scope.EMAIL in scopes) user.primaryEmail.display else null,
        emailVerified = if (Scope.EMAIL in scopes) user.isEmailVerified else null,
        updatedAt = if (Scope.PROFILE in scopes) user.updatedAt.epochSecond else null,
    )
