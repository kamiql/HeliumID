package dev.kamiql.helium.oauth

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.Consent
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.client.Scope
import dev.kamiql.helium.domain.common.AuthorizationCodeId
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.ConsentId
import dev.kamiql.helium.domain.common.RefreshTokenFamilyId
import dev.kamiql.helium.domain.common.RefreshTokenId
import dev.kamiql.helium.domain.common.Secret
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.crypto.RandomSource
import dev.kamiql.helium.domain.crypto.TokenHasher
import dev.kamiql.helium.domain.error.AuthError
import dev.kamiql.helium.domain.event.DomainEvent
import dev.kamiql.helium.domain.policy.Lifetimes
import dev.kamiql.helium.domain.repository.AuthorizationCodeRepository
import dev.kamiql.helium.domain.repository.ClientRepository
import dev.kamiql.helium.domain.repository.ConsentRepository
import dev.kamiql.helium.domain.repository.RefreshTokenRepository
import dev.kamiql.helium.domain.repository.RevokedTokenRepository
import dev.kamiql.helium.domain.repository.SessionRepository
import dev.kamiql.helium.domain.repository.UserRepository
import dev.kamiql.helium.domain.session.AuthenticationMethod
import dev.kamiql.helium.domain.token.AuthorizationCode
import dev.kamiql.helium.domain.token.RefreshToken
import dev.kamiql.helium.domain.token.RefreshTokenFamily
import dev.kamiql.helium.flow.Flow
import dev.kamiql.helium.flow.FlowId
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.FlowStateKey
import dev.kamiql.helium.flow.StepResult
import dev.kamiql.helium.flow.TransactionPolicy
import dev.kamiql.helium.flow.effect
import dev.kamiql.helium.flow.flow
import dev.kamiql.helium.flow.port.RateLimit
import dev.kamiql.helium.flow.port.RateLimiter
import dev.kamiql.helium.flow.requirement.RateLimited
import dev.kamiql.helium.flow.step
import org.slf4j.LoggerFactory
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Instant

/**
 * The OAuth 2 / OIDC protocol flows.
 *
 * Read these alongside RFC 6749 §4.1, RFC 7636 and OIDC Core §3.1 — the structure follows the
 * specifications deliberately, because deviating from them is how authorization servers grow
 * holes.
 *
 * The three properties everything else hangs off:
 *
 *  1. **The redirect URI is matched exactly**, and no error is ever redirected to an
 *     unvalidated URI. Getting this wrong turns the server into an open redirector and
 *     leaks authorization codes.
 *  2. **PKCE S256 is mandatory** for every client, not only public ones.
 *  3. **Refresh tokens rotate, and reuse kills the family.** A used token presented again is
 *     indistinguishable from theft, so it is treated as theft.
 */
class OAuthFlows(
    private val issuerUrl: String,
    private val clients: ClientRepository,
    private val users: UserRepository,
    private val sessions: SessionRepository,
    private val consents: ConsentRepository,
    private val codes: AuthorizationCodeRepository,
    private val refreshTokens: RefreshTokenRepository,
    private val revokedTokens: RevokedTokenRepository,
    private val tokenIssuer: TokenIssuer,
    private val tokenHasher: TokenHasher,
    private val random: RandomSource,
    private val rateLimiter: RateLimiter,
    /**
     * Used only to commit a compromise response independently of the request that failed.
     * See [revokeCompromisedFamily].
     */
    private val transactionManager: dev.kamiql.helium.flow.port.TransactionManager,
    private val outbox: dev.kamiql.helium.flow.port.OutboxPort,
    private val lifetimes: Lifetimes = Lifetimes.DEFAULT,
) {

    private val log = LoggerFactory.getLogger(OAuthFlows::class.java)

    private val resultKey = FlowStateKey<AuthorizeResult>("authorize_result")
    private val tokenResponseKey = FlowStateKey<TokenResponse>("token_response", sensitive = true)
    private val subjectKey = FlowStateKey<UserId>("oauth_subject")

    // =========================================================================
    // authorization endpoint
    // =========================================================================

    /**
     * `GET /oauth2/authorize`.
     *
     * Validation order is load-bearing. The client and the redirect URI are checked **first**,
     * because until both are known good there is nowhere safe to send an error; anything that
     * fails before that point must be rendered directly by the authorization server.
     */
    val authorize: Flow<AuthorizeCommand, AuthorizeResult> =
        flow(FlowId("oauth.authorize")) {
            transaction(TransactionPolicy.Required)
            auditAs("oauth.authorize")

            step(
                step("validate-and-issue-code") { command, context, state ->
                    val client = clients.findById(ClientId(command.clientId))
                        ?.takeIf { it.enabled }
                        ?: return@step StepResult.Fail(AuthError.UnauthorizedClient)

                    // Exact match, no normalization. See OAuthClient.allowsRedirectUri.
                    if (!client.allowsRedirectUri(command.redirectUri)) {
                        log.warn("rejected unregistered redirect URI for client {}", client.clientId)
                        return@step StepResult.Fail(AuthError.RedirectUriInvalid)
                    }

                    // From here on the redirect URI is trusted, so protocol errors may be
                    // reported to it as RFC 6749 §4.1.2.1 requires.
                    if (command.responseType != "code") {
                        return@step StepResult.Fail(AuthError.ValidationFailed(mapOf("response_type" to "unsupported")))
                    }
                    if (GrantType.AUTHORIZATION_CODE !in client.allowedGrantTypes) {
                        return@step StepResult.Fail(AuthError.UnauthorizedClient)
                    }

                    val challengeMethod = Pkce.validateChallenge(command.codeChallenge, command.codeChallengeMethod)
                        ?: return@step StepResult.Fail(AuthError.PkceVerifierInvalid)

                    val requested = command.scope.split(' ').filter { it.isNotBlank() }.toSet()
                    val rejected = client.rejectedScopes(requested)
                    if (rejected.isNotEmpty()) {
                        return@step StepResult.Fail(AuthError.InvalidScope(rejected))
                    }

                    val returnTo = command.originalRequestUrl(issuerUrl)

                    // --- is there a usable session? ---
                    val session = command.sessionId?.let { sessions.findById(it) }
                        ?.takeIf { it.isActive(context.now) }
                    if (session == null || command.prompt == "login") {
                        state[resultKey] = AuthorizeResult.LoginRequired(returnTo)
                        return@step StepResult.Continue
                    }

                    val user = users.findById(session.userId)
                        ?: return@step StepResult.Fail(AuthError.AuthenticationRequired)
                    user.toAccessError()?.let { return@step StepResult.Fail(it) }

                    // --- consent ---
                    val existingConsent = consents.find(user.id, client.clientId)
                    val needsConsent = !client.skipConsent &&
                        !command.consentGranted &&
                        existingConsent?.covers(requested) != true

                    if (needsConsent) {
                        if (command.prompt == "none") {
                            // OIDC `prompt=none` means "do not interact"; asking would violate it.
                            return@step StepResult.Fail(AuthError.ConsentRequired)
                        }
                        val catalogue = clients.listScopes().associateBy { it.name }
                        state[resultKey] = AuthorizeResult.ConsentRequired(
                            clientName = client.name,
                            clientId = client.clientId,
                            scopes = requested
                                .filterNot { catalogue[it]?.implicit == true }
                                .map { ConsentScope(it, catalogue[it]?.description ?: it) },
                            returnTo = returnTo,
                        )
                        return@step StepResult.Continue
                    }

                    if (command.consentGranted && existingConsent?.covers(requested) != true) {
                        consents.grant(
                            Consent(
                                id = ConsentId.random(),
                                userId = user.id,
                                clientId = client.clientId,
                                grantedScopes = requested + existingConsent?.grantedScopes.orEmpty(),
                                grantedAt = context.now,
                                revokedAt = null,
                            ),
                        )
                    }

                    // --- mint the code ---
                    val plaintext = random.token(32)
                    val code = AuthorizationCode(
                        id = AuthorizationCodeId.random(),
                        codeHash = tokenHasher.hash(plaintext),
                        clientId = client.clientId,
                        userId = user.id,
                        sessionId = session.id,
                        // Captured now so the token exchange cannot be steered to a different
                        // URI later.
                        redirectUri = command.redirectUri,
                        scopes = requested,
                        nonce = command.nonce,
                        codeChallenge = command.codeChallenge!!,
                        codeChallengeMethod = challengeMethod,
                        authenticationMethods = session.authenticationMethods,
                        authenticatedAt = session.authenticatedAt,
                        issuedAt = context.now,
                        expiresAt = context.now.plus(lifetimes.authorizationCode),
                        consumedAt = null,
                    )
                    codes.insert(code)

                    state[subjectKey] = user.id
                    state[resultKey] = AuthorizeResult.Redirect(
                        buildString {
                            append(command.redirectUri)
                            append(if ('?' in command.redirectUri) '&' else '?')
                            append("code=").append(encode(plaintext))
                            command.state?.let { append("&state=").append(encode(it)) }
                        },
                    )
                    StepResult.Continue
                },
            )

            result { state -> state.require(resultKey) }
        }

    // =========================================================================
    // token endpoint
    // =========================================================================

    /**
     * `POST /oauth2/token`.
     *
     * Supports `authorization_code`, `refresh_token` and `client_credentials`. The password
     * grant is absent and must stay absent (CLAUDE.md).
     */
    val token: Flow<TokenCommand, TokenResponse> =
        flow(FlowId("oauth.token")) {
            transaction(TransactionPolicy.Required)
            auditAs("oauth.token")

            require(
                RateLimited<TokenCommand>("token.client", RateLimit.TOKEN_ENDPOINT, rateLimiter) { command, context ->
                    command.clientId ?: context.ipAddress
                },
            )

            step(
                step("exchange") { command, context, state ->
                    if (command.grantType in GrantType.FORBIDDEN_WIRE_VALUES) {
                        log.warn("rejected forbidden grant type {}", command.grantType)
                        return@step StepResult.Fail(AuthError.UnauthorizedClient)
                    }
                    val grant = GrantType.parse(command.grantType)
                        ?: return@step StepResult.Fail(
                            AuthError.ValidationFailed(mapOf("grant_type" to "unsupported")),
                        )

                    val client = authenticateClient(command.clientId, command.clientSecret)
                        ?: return@step StepResult.Fail(AuthError.UnauthorizedClient)
                    if (grant !in client.allowedGrantTypes) {
                        return@step StepResult.Fail(AuthError.UnauthorizedClient)
                    }

                    when (grant) {
                        GrantType.AUTHORIZATION_CODE ->
                            exchangeAuthorizationCode(command, client, context.now, state)
                        GrantType.REFRESH_TOKEN ->
                            exchangeRefreshToken(command, client, context.now, state)
                        GrantType.CLIENT_CREDENTIALS ->
                            issueClientCredentials(command, client, context.now, state)
                    }
                },
            )

            result { state -> state.require(tokenResponseKey) }
        }

    private suspend fun exchangeAuthorizationCode(
        command: TokenCommand,
        client: OAuthClient,
        now: Instant,
        state: dev.kamiql.helium.flow.MutableFlowState,
    ): StepResult {
        val presented = command.code ?: return StepResult.Fail(AuthError.InvalidGrant)
        val verifier = command.codeVerifier ?: return StepResult.Fail(AuthError.PkceVerifierInvalid)

        val code = codes.findByHash(tokenHasher.hash(presented))
            ?: return StepResult.Fail(AuthError.InvalidGrant)

        // RFC 6749 §4.1.3: the code must have been issued to this client and this redirect URI.
        if (code.clientId != client.clientId) {
            log.warn("client {} presented a code issued to {}", client.clientId, code.clientId)
            return StepResult.Fail(AuthError.InvalidGrant)
        }
        if (command.redirectUri != code.redirectUri) {
            return StepResult.Fail(AuthError.InvalidGrant)
        }
        if (!Pkce.verify(verifier, code.codeChallenge, code.codeChallengeMethod)) {
            return StepResult.Fail(AuthError.PkceVerifierInvalid)
        }

        // Single use, enforced atomically. A `false` here means the code was already redeemed:
        // RFC 6819 §5.2.1.1 says to revoke everything previously issued from it, because one of
        // the two presenters is an attacker and we cannot tell which.
        if (!codes.consume(code.id, now)) {
            log.warn("authorization code replay detected for client {}", client.clientId)
            refreshTokens.revokeFamiliesForUser(code.userId, now)
            return StepResult.Fail(AuthError.InvalidGrant)
        }

        val user = users.findById(code.userId) ?: return StepResult.Fail(AuthError.InvalidGrant)
        user.toAccessError()?.let { return StepResult.Fail(it) }

        val access = tokenIssuer.issueAccessToken(
            userId = user.id,
            client = client,
            scopes = code.scopes,
            methods = code.authenticationMethods,
            sessionId = code.sessionId,
            now = now,
        )

        val refresh = if (GrantType.REFRESH_TOKEN in client.allowedGrantTypes) {
            issueFreshFamily(user.id, client, code.scopes, code.sessionId, code.authenticationMethods, now)
        } else {
            null
        }

        val idToken = if (Scope.OPENID in code.scopes) {
            tokenIssuer.issueIdToken(
                user = user,
                client = client,
                scopes = code.scopes,
                nonce = code.nonce,
                methods = code.authenticationMethods,
                authenticatedAt = code.authenticatedAt,
                now = now,
            )
        } else {
            null
        }

        state[subjectKey] = user.id
        state[tokenResponseKey] = TokenResponse(
            accessToken = access.token,
            expiresIn = lifetimes.accessToken.seconds,
            refreshToken = refresh,
            idToken = idToken,
            scope = code.scopes.sorted().joinToString(" "),
        )
        return StepResult.Continue
    }

    /**
     * Refresh rotation with reuse detection (concept §4.3).
     *
     * Every refresh mints a replacement and marks the presented token used. Presenting a used
     * token later means either the client replayed it or somebody stole it — and since those
     * are indistinguishable, the entire family is revoked and the user must sign in again.
     */
    private suspend fun exchangeRefreshToken(
        command: TokenCommand,
        client: OAuthClient,
        now: Instant,
        state: dev.kamiql.helium.flow.MutableFlowState,
    ): StepResult {
        val presented = command.refreshToken ?: return StepResult.Fail(AuthError.InvalidGrant)
        val stored = refreshTokens.findByHash(tokenHasher.hash(presented.reveal()))
            ?: return StepResult.Fail(AuthError.InvalidGrant)

        val family = refreshTokens.findFamily(stored.familyId)
            ?: return StepResult.Fail(AuthError.InvalidGrant)

        if (family.clientId != client.clientId) {
            log.warn("client {} presented a refresh token from family of {}", client.clientId, family.clientId)
            return StepResult.Fail(AuthError.InvalidGrant)
        }

        if (stored.usedAt != null) {
            revokeCompromisedFamily(family, client, now)
            state[subjectKey] = family.userId
            return StepResult.Fail(AuthError.InvalidGrant)
        }

        if (!stored.isRedeemable(now) || !family.isActive(now)) {
            return StepResult.Fail(AuthError.InvalidGrant)
        }

        val user = users.findById(family.userId) ?: return StepResult.Fail(AuthError.InvalidGrant)
        user.toAccessError()?.let { return StepResult.Fail(it) }

        // Narrowing scope on refresh is allowed (RFC 6749 §6); widening never is.
        val requested = command.scope?.split(' ')?.filter { it.isNotBlank() }?.toSet()
        val scopes = when {
            requested == null -> family.scopes
            family.scopes.containsAll(requested) -> requested
            else -> return StepResult.Fail(AuthError.InvalidScope(requested - family.scopes))
        }

        val replacement = RefreshToken(
            id = RefreshTokenId.random(),
            familyId = family.id,
            tokenHash = "",
            issuedAt = now,
            expiresAt = minOf(now.plus(lifetimes.refreshTokenInactivity), family.absoluteExpiresAt),
            usedAt = null,
            revokedAt = null,
            replacedByTokenId = null,
        )

        // Conditional UPDATE: if two requests race with the same token, exactly one wins and
        // the loser is treated as reuse.
        if (!refreshTokens.markUsed(stored.id, now, replacement.id)) {
            // Lost the race: another request already rotated this exact token. From here the two
            // are indistinguishable from a replay, so it is treated as one.
            revokeCompromisedFamily(family, client, now)
            return StepResult.Fail(AuthError.InvalidGrant)
        }

        val plaintext = random.token(32)
        refreshTokens.insertToken(replacement.copy(tokenHash = tokenHasher.hash(plaintext)))

        val access = tokenIssuer.issueAccessToken(
            userId = user.id,
            client = client,
            scopes = scopes,
            methods = family.authenticationMethods,
            sessionId = family.sessionId,
            now = now,
        )

        state[subjectKey] = user.id
        state[tokenResponseKey] = TokenResponse(
            accessToken = access.token,
            expiresIn = lifetimes.accessToken.seconds,
            refreshToken = plaintext,
            idToken = null,
            scope = scopes.sorted().joinToString(" "),
        )
        return StepResult.Continue
    }

    /** `client_credentials`: a machine acting for itself. There is no user and no refresh token. */
    private suspend fun issueClientCredentials(
        command: TokenCommand,
        client: OAuthClient,
        now: Instant,
        state: dev.kamiql.helium.flow.MutableFlowState,
    ): StepResult {
        if (client.type != ClientType.CONFIDENTIAL) {
            // A public client cannot keep a secret, so it cannot have an identity of its own.
            return StepResult.Fail(AuthError.UnauthorizedClient)
        }
        val requested = command.scope?.split(' ')?.filter { it.isNotBlank() }?.toSet() ?: client.allowedScopes
        val rejected = client.rejectedScopes(requested)
        if (rejected.isNotEmpty()) return StepResult.Fail(AuthError.InvalidScope(rejected))

        val access = tokenIssuer.issueAccessToken(
            userId = null,
            client = client,
            scopes = requested,
            methods = emptySet(),
            sessionId = null,
            now = now,
        )
        state[tokenResponseKey] = TokenResponse(
            accessToken = access.token,
            expiresIn = lifetimes.accessToken.seconds,
            refreshToken = null,
            idToken = null,
            scope = requested.sorted().joinToString(" "),
        )
        return StepResult.Continue
    }

    /**
     * Revokes a family whose token was replayed, and notifies the account owner.
     *
     * Runs in its **own** transaction. The caller fails the request immediately afterwards, and a
     * failure unwinds the flow's transaction — so revoking inside it would undo the revocation
     * and leave the attacker's replay entirely without consequence. This is the one place in the
     * codebase where a write must deliberately outlive the request that produced it.
     *
     * The outbox event is written here too, for the same reason: concept §4.10 requires the user
     * to be told about token reuse, and an effect declared on the flow would only fire on success.
     */
    private suspend fun revokeCompromisedFamily(
        family: RefreshTokenFamily,
        client: OAuthClient,
        now: Instant,
    ) {
        log.error(
            "refresh token reuse detected for user {} and client {}; revoking family {}",
            family.userId, client.clientId, family.id,
        )
        runCatching {
            transactionManager.requiresNew {
                refreshTokens.revokeFamily(family.id, now, reuseDetected = true)
                outbox.publish(
                    events = listOf(DomainEvent.RefreshTokenReuseDetected(family.userId, client.clientId)),
                    context = dev.kamiql.helium.flow.port.OutboxContext(
                        requestId = dev.kamiql.helium.domain.common.RequestId("token-reuse"),
                        occurredAt = now,
                    ),
                )
            }
        }.onFailure {
            // Never let the compromise response mask the rejection: the caller must still be
            // told `invalid_grant`, and the failure to revoke needs to be screamingly visible.
            log.error("FAILED to revoke compromised family {}; tokens may still be live", family.id, it)
        }
    }

    private suspend fun issueFreshFamily(
        userId: UserId,
        client: OAuthClient,
        scopes: Set<String>,
        sessionId: dev.kamiql.helium.domain.common.SessionId?,
        methods: Set<AuthenticationMethod>,
        now: Instant,
    ): String {
        val family = refreshTokens.createFamily(
            RefreshTokenFamily(
                id = RefreshTokenFamilyId.random(),
                userId = userId,
                clientId = client.clientId,
                sessionId = sessionId,
                scopes = scopes,
                authenticationMethods = methods,
                createdAt = now,
                absoluteExpiresAt = now.plus(lifetimes.refreshTokenAbsolute),
                revokedAt = null,
                reuseDetectedAt = null,
            ),
        )
        val plaintext = random.token(32)
        refreshTokens.insertToken(
            RefreshToken(
                id = RefreshTokenId.random(),
                familyId = family.id,
                tokenHash = tokenHasher.hash(plaintext),
                issuedAt = now,
                expiresAt = now.plus(lifetimes.refreshTokenInactivity),
                usedAt = null,
                revokedAt = null,
                replacedByTokenId = null,
            ),
        )
        return plaintext
    }

    // =========================================================================
    // revocation and introspection
    // =========================================================================

    /**
     * `POST /oauth2/revoke` (RFC 7009).
     *
     * Always answers `200`, even for an unknown token. The RFC requires it, and it stops the
     * endpoint from becoming a token-validity oracle.
     */
    val revoke: Flow<RevokeCommand, Unit> =
        flow(FlowId("oauth.revoke")) {
            transaction(TransactionPolicy.Required)

            step(
                step("revoke") { command, context, _ ->
                    val client = authenticateClient(command.clientId, command.clientSecret)
                        ?: return@step StepResult.Fail(AuthError.UnauthorizedClient)

                    val hash = tokenHasher.hash(command.token.reveal())
                    val refresh = refreshTokens.findByHash(hash)
                    if (refresh != null) {
                        val family = refreshTokens.findFamily(refresh.familyId)
                        // Only the client that owns the family may revoke it; otherwise any
                        // registered client could sign out another client's users.
                        if (family != null && family.clientId == client.clientId) {
                            refreshTokens.revokeFamily(family.id, context.now, reuseDetected = false)
                        }
                        return@step StepResult.Continue
                    }

                    // Not a refresh token — try it as an access token JWT.
                    val verified = tokenIssuer.verify(command.token.reveal(), now = context.now)
                    if (verified != null && verified.clientId == client.clientId) {
                        revokedTokens.revoke(verified.tokenId, verified.expiresAt, context.now)
                    }
                    StepResult.Continue
                },
            )

            result { }
        }

    /**
     * `POST /oauth2/introspect` (RFC 7662).
     *
     * This is what gives JWT access tokens central revocation: the signature says the token was
     * legitimately issued, the deny list says whether it still counts.
     */
    suspend fun introspect(command: IntrospectCommand, now: Instant): IntrospectionResponse {
        authenticateClient(command.clientId, command.clientSecret) ?: return IntrospectionResponse.INACTIVE

        val raw = command.token.reveal()

        val verified = tokenIssuer.verify(raw, now = now)
        if (verified != null) {
            if (revokedTokens.isRevoked(verified.tokenId)) return IntrospectionResponse.INACTIVE
            // A revoked session invalidates the tokens it produced, even before they expire.
            verified.sessionId?.let { sessionId ->
                val session = sessions.findById(sessionId)
                if (session != null && !session.isActive(now)) return IntrospectionResponse.INACTIVE
            }
            val username = verified.userId?.let { users.findById(it)?.username?.display }
            return IntrospectionResponse(
                active = true,
                scope = verified.scopes.sorted().joinToString(" "),
                clientId = verified.clientId?.value,
                username = username,
                tokenType = "Bearer",
                exp = verified.expiresAt.epochSecond,
                iat = verified.issuedAt.epochSecond,
                sub = verified.subject,
                aud = verified.audience.toList(),
                iss = issuerUrl,
                jti = verified.tokenId,
            )
        }

        val refresh = refreshTokens.findByHash(tokenHasher.hash(raw)) ?: return IntrospectionResponse.INACTIVE
        val family = refreshTokens.findFamily(refresh.familyId) ?: return IntrospectionResponse.INACTIVE
        if (!refresh.isRedeemable(now) || !family.isActive(now)) return IntrospectionResponse.INACTIVE

        return IntrospectionResponse(
            active = true,
            scope = family.scopes.sorted().joinToString(" "),
            clientId = family.clientId.value,
            tokenType = "refresh_token",
            exp = refresh.expiresAt.epochSecond,
            iat = refresh.issuedAt.epochSecond,
            sub = family.userId.value.toString(),
            iss = issuerUrl,
        )
    }

    /**
     * Authenticates the client on the token, revoke and introspect endpoints.
     *
     * Public clients present only a `client_id` and are authenticated by PKCE instead; the
     * secret comparison is constant time and a public client presenting a secret is rejected
     * rather than quietly accepted.
     */
    suspend fun authenticateClient(clientId: String?, secret: Secret?): OAuthClient? {
        if (clientId.isNullOrBlank()) return null
        val client = clients.findById(ClientId(clientId))?.takeIf { it.enabled } ?: return null

        return when (client.type) {
            ClientType.PUBLIC -> if (secret == null) client else null
            ClientType.CONFIDENTIAL -> {
                val presented = secret ?: return null
                val expected = client.secretHash ?: return null
                if (tokenHasher.matches(presented.reveal(), expected)) client else null
            }
        }
    }

    /** Marks a user's audit subject when the actor is a client rather than the user. */
    internal fun subjectMetadata(state: dev.kamiql.helium.flow.FlowState): Map<String, String> =
        state[subjectKey]?.let { mapOf(FlowRunner.SUBJECT_USER_ID to it.value.toString()) }.orEmpty()
}

private fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

/**
 * Rebuilds the authorization request URL so the login and consent screens can send the user
 * back to exactly where they were.
 *
 * Built from validated fields only — never by echoing the raw query string, which would let a
 * caller smuggle arbitrary parameters into the return URL.
 */
private fun AuthorizeCommand.originalRequestUrl(issuerUrl: String): String = buildString {
    append(issuerUrl.trimEnd('/')).append("/oauth2/authorize")
    append("?response_type=").append(encode(responseType))
    append("&client_id=").append(encode(clientId))
    append("&redirect_uri=").append(encode(redirectUri))
    append("&scope=").append(encode(scope))
    state?.let { append("&state=").append(encode(it)) }
    nonce?.let { append("&nonce=").append(encode(it)) }
    codeChallenge?.let { append("&code_challenge=").append(encode(it)) }
    codeChallengeMethod?.let { append("&code_challenge_method=").append(encode(it)) }
}
