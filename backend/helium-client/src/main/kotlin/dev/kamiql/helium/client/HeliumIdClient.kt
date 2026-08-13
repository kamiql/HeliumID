package dev.kamiql.helium.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.encodeURLPathPart
import io.ktor.http.parameters
import io.ktor.serialization.kotlinx.json.json
import java.util.Base64
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * A typed, suspending client for every HeliumID HTTP endpoint.
 *
 * One instance is thread-safe and is meant to be long-lived — it wraps a single [HttpClient]
 * and its connection pool. Create it once per identity server and share it.
 *
 * Every method throws [HeliumApiException] carrying a sealed [HeliumError] when the server
 * refuses, and [HeliumTransportException] when there was no usable answer at all. Nothing
 * returns a nullable "maybe it worked".
 *
 * Usage:
 * ```kotlin
 * val client = HeliumIdClient.create("https://id.example") {
 *     // Bearer credentials for the /v1/me and /v1/admin surfaces.
 *     bearerToken { tokenStore.currentAccessToken() }
 * }
 *
 * // Authorization code + PKCE, the only interactive flow this SDK supports.
 * val pkce = Pkce.generate()
 * val authorizeUrl = client.authorizationUrl(
 *     clientId = "orders-web",
 *     redirectUri = "https://orders.example/callback",
 *     scope = setOf("openid", "profile", "orders:read"),
 *     state = Pkce.generateState(),
 *     codeChallenge = pkce.challenge,
 * )
 * // ...user comes back with ?code=...
 * val tokens = client.exchangeAuthorizationCode(
 *     code = code,
 *     redirectUri = "https://orders.example/callback",
 *     clientId = "orders-web",
 *     codeVerifier = pkce.verifier,
 * )
 * ```
 *
 * ### Credentials
 * Two authentication styles reach the same endpoints:
 *
 *  * **Bearer** — configure [HeliumIdClientConfig.bearerToken]. This is the right choice for
 *    service-to-service calls and native apps. Bearer requests are exempt from CSRF checks
 *    because a browser will not attach an `Authorization` header cross-site.
 *  * **Cookie session** — supply a cookie-aware [HttpClient] plus
 *    [HeliumIdClientConfig.csrfToken]. State-changing calls then carry the `X-CSRF-Token`
 *    header the server's double-submit check requires.
 *
 * Never put a long-lived token in browser `localStorage`; that is what the cookie session is
 * for.
 */
public class HeliumIdClient private constructor(
    private val baseUrl: String,
    private val http: HttpClient,
    private val ownsHttpClient: Boolean,
    private val bearerToken: (suspend () -> String?)?,
    private val csrfToken: (suspend () -> String?)?,
) : AutoCloseable {

    /**
     * Wraps an [HttpClient] you already own.
     *
     * The supplied client is reconfigured (JSON negotiation is added) into a derived client
     * that shares the same engine, so [close] here does not shut down your engine. Use this
     * when you need a specific engine, a proxy, mTLS, or cookie support.
     *
     * @param baseUrl the issuer origin, e.g. `https://id.example`. Must be HTTPS outside
     *        local development: everything below is a bearer credential in transit.
     */
    public constructor(baseUrl: String, httpClient: HttpClient) : this(
        baseUrl = normalizeBaseUrl(baseUrl),
        http = httpClient.withHeliumDefaults(),
        ownsHttpClient = false,
        bearerToken = null,
        csrfToken = null,
    )

    public companion object {

        /**
         * Builds a client with a bundled CIO engine and sane timeouts.
         *
         * @param baseUrl the issuer origin, e.g. `https://id.example`.
         * @param configure timeouts and credential suppliers; see [HeliumIdClientConfig].
         */
        public fun create(
            baseUrl: String,
            configure: HeliumIdClientConfig.() -> Unit = {},
        ): HeliumIdClient {
            val config = HeliumIdClientConfig().apply(configure)
            val supplied = config.httpClient
            val engineClient = supplied ?: HttpClient(CIO)
            return HeliumIdClient(
                baseUrl = normalizeBaseUrl(baseUrl),
                http = engineClient.withHeliumDefaults(config),
                ownsHttpClient = supplied == null,
                bearerToken = config.bearerTokenProvider,
                csrfToken = config.csrfTokenProvider,
            )
        }
    }

    /**
     * A view of this client that presents [accessToken] on every request.
     *
     * Cheap: the underlying [HttpClient] is shared, so the copy costs one object. Handy for
     * acting as a specific user inside a request scope without threading a token supplier
     * through your call stack.
     *
     * The returned client does not own the engine — [close] on it is a no-op.
     */
    public fun withBearerToken(accessToken: String): HeliumIdClient = HeliumIdClient(
        baseUrl = baseUrl,
        http = http,
        ownsHttpClient = false,
        bearerToken = { accessToken },
        csrfToken = csrfToken,
    )

    /** Releases the engine, if this client created one. Safe to call more than once. */
    override fun close() {
        if (ownsHttpClient) http.close()
    }

    // --- OAuth 2 / OIDC protocol ------------------------------------------------------

    /**
     * Builds the `/oauth2/authorize` URL to send the user agent to.
     *
     * Authorization Code with PKCE S256 is the only interactive flow HeliumID accepts; there is
     * no implicit grant and no password grant, and this builder cannot produce one.
     *
     * @param state opaque, single-use, bound to the user agent. Verify it on the callback —
     *        PKCE does not replace it, it protects a different thing.
     * @param codeChallenge from [Pkce.challengeFor]. Required: an authorization request without
     *        one is rejected rather than downgraded.
     * @param nonce recommended for `openid` requests; check it against the ID token's `nonce`.
     * @param prompt `login`, `consent` or `none`, per OIDC Core §3.1.2.1.
     */
    public fun authorizationUrl(
        clientId: String,
        redirectUri: String,
        scope: Set<String>,
        state: String,
        codeChallenge: String,
        nonce: String? = null,
        prompt: String? = null,
    ): String {
        val query = buildList {
            add("response_type" to "code")
            add("client_id" to clientId)
            add("redirect_uri" to redirectUri)
            add("scope" to scope.joinToString(" "))
            add("state" to state)
            add("code_challenge" to codeChallenge)
            add("code_challenge_method" to "S256")
            nonce?.let { add("nonce" to it) }
            prompt?.let { add("prompt" to it) }
        }.joinToString("&") { (k, v) -> "$k=${v.encodeURLParameter()}" }
        return "$baseUrl/oauth2/authorize?$query"
    }

    /**
     * Exchanges an authorization code for tokens (`grant_type=authorization_code`).
     *
     * @param codeVerifier the verifier whose challenge was sent with the authorization request.
     * @param clientSecret only for confidential clients; sent as `client_secret_basic`, which
     *        RFC 6749 §2.3.1 prefers over putting it in the body. Public clients pass `null` and
     *        rely on PKCE.
     * @throws HeliumApiException with [HeliumError.InvalidGrant] if the code is expired, already
     *         spent, or the verifier does not match.
     */
    public suspend fun exchangeAuthorizationCode(
        code: String,
        redirectUri: String,
        clientId: String,
        codeVerifier: String,
        clientSecret: String? = null,
    ): TokenEndpointResponse = tokenRequest(clientId, clientSecret) {
        append("grant_type", "authorization_code")
        append("code", code)
        append("redirect_uri", redirectUri)
        append("code_verifier", codeVerifier)
    }

    /**
     * Exchanges a refresh token for a new access token (`grant_type=refresh_token`).
     *
     * Refresh tokens **rotate**. The response contains a new refresh token that replaces the one
     * you sent; persist it before you use the access token, and never retry a failed refresh
     * with the old value. Presenting a spent token is treated as theft and revokes the whole
     * family, signing every device out.
     *
     * @throws HeliumApiException with [HeliumError.InvalidGrant] when the token was expired,
     *         revoked, or already used. Re-authenticate; do not retry.
     */
    public suspend fun refresh(
        refreshToken: String,
        clientId: String,
        clientSecret: String? = null,
        scope: Set<String>? = null,
    ): TokenEndpointResponse = tokenRequest(clientId, clientSecret) {
        append("grant_type", "refresh_token")
        append("refresh_token", refreshToken)
        scope?.let { append("scope", it.joinToString(" ")) }
    }

    /**
     * Obtains a token for the client itself (`grant_type=client_credentials`).
     *
     * There is no user behind this token: it carries `token_use=client_credentials` and its
     * `sub` is the client id. Scopes are its only authority — it inherits no user permissions.
     */
    public suspend fun clientCredentials(
        clientId: String,
        clientSecret: String,
        scope: Set<String>? = null,
    ): TokenEndpointResponse = tokenRequest(clientId, clientSecret) {
        append("grant_type", "client_credentials")
        scope?.let { append("scope", it.joinToString(" ")) }
    }

    /**
     * Revokes an access or refresh token (RFC 7009).
     *
     * Always succeeds for a well-formed request, including for a token that never existed —
     * otherwise the endpoint would be an oracle for testing token validity.
     *
     * @param tokenTypeHint `access_token` or `refresh_token`; an optimisation, not a constraint.
     */
    public suspend fun revoke(
        token: String,
        clientId: String,
        clientSecret: String? = null,
        tokenTypeHint: String? = null,
    ) {
        val response = call(HttpMethod.Post, "/oauth2/revoke") {
            clientAuth(clientId, clientSecret)
            setBody(
                FormDataContent(
                    parameters {
                        append("token", token)
                        tokenTypeHint?.let { append("token_type_hint", it) }
                        if (clientSecret == null) append("client_id", clientId)
                    },
                ),
            )
        }
        response.heliumEnsureSuccess()
    }

    /**
     * Asks the authorization server whether a token is still active (RFC 7662).
     *
     * Requires client authentication: this endpoint reads other parties' tokens. Prefer offline
     * JWKS verification for per-request checks and reserve this for the cases where instant
     * revocation matters — see the README's "offline verification vs introspection".
     */
    public suspend fun introspect(
        token: String,
        clientId: String,
        clientSecret: String,
    ): IntrospectionResponse = call(HttpMethod.Post, "/oauth2/introspect") {
        clientAuth(clientId, clientSecret)
        setBody(FormDataContent(parameters { append("token", token) }))
    }.heliumBody()

    /** The OIDC discovery document. Cacheable; the server sets `max-age=300`. */
    public suspend fun discovery(): DiscoveryResponse =
        call(HttpMethod.Get, "/.well-known/openid-configuration").heliumBody()

    /**
     * The raw JWKS document.
     *
     * Returned as text rather than parsed: the only sane consumer is a JOSE library, and
     * re-serialising a JWK through an intermediate model is a good way to corrupt it. The server
     * plugin does not use this — it lets Nimbus fetch and cache JWKS itself.
     */
    public suspend fun jwks(): String {
        val response = call(HttpMethod.Get, "/.well-known/jwks.json")
        response.heliumEnsureSuccess()
        return response.bodyAsText()
    }

    /** OIDC `userinfo`. The claims returned are gated on the token's scopes. */
    public suspend fun userInfo(accessToken: String): UserInfoResponse =
        call(HttpMethod.Get, "/userinfo") {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
        }.heliumBody()

    // --- /v1/auth ----------------------------------------------------------------------

    /**
     * Whoami plus a fresh CSRF token, for a browser session.
     *
     * Always `200`, even when anonymous. Requires a cookie-aware [HttpClient].
     */
    public suspend fun session(): SessionBootstrapResponse =
        call(HttpMethod.Get, "/v1/auth/session").heliumBody()

    /** The password policy, so a UI can validate live instead of guessing. */
    public suspend fun passwordRequirements(): PasswordRequirementsResponse =
        call(HttpMethod.Get, "/v1/auth/password-requirements").heliumBody()

    /**
     * Registers a local account.
     *
     * Answers `202` with an opaque body whether or not the account was created. That is not a
     * bug to work around: it is what stops registration from confirming which addresses are
     * already in use.
     */
    public suspend fun register(request: RegisterRequest): AcceptedResponse =
        call(HttpMethod.Post, "/v1/auth/register") { jsonBody(request) }.heliumBody()

    /**
     * Signs in with a password and establishes a session cookie.
     *
     * @throws HeliumApiException with [HeliumError.MfaRequired] when a second factor is needed —
     *         the common case for protected accounts, not an error condition. Continue with
     *         [verifyMfa].
     * @throws HeliumApiException with [HeliumError.InvalidCredentials] for a wrong password, an
     *         unknown identifier, or an account with no password credential. All three are
     *         indistinguishable on purpose.
     */
    public suspend fun login(identifier: String, password: String) {
        call(HttpMethod.Post, "/v1/auth/login") {
            jsonBody(LoginRequest(identifier, password))
        }.heliumEnsureSuccess()
    }

    /**
     * Completes an MFA challenge raised by [login].
     *
     * @param transactionId from [HeliumError.MfaRequired.transactionId]. One-time: a failed
     *        attempt does not necessarily invalidate it, but an expired one cannot be renewed.
     * @param method `totp` or `recovery_code`.
     */
    public suspend fun verifyMfa(transactionId: String, method: String, code: String) {
        call(HttpMethod.Post, "/v1/auth/mfa/verify") {
            jsonBody(MfaVerifyRequest(transactionId, method, code))
        }.heliumEnsureSuccess()
    }

    /** Ends the current browser session. Idempotent: already signed out is still success. */
    public suspend fun logout() {
        call(HttpMethod.Post, "/v1/auth/logout").heliumEnsureSuccess()
    }

    /** Confirms an email address with the one-time token from the verification mail. */
    public suspend fun verifyEmail(token: String) {
        call(HttpMethod.Post, "/v1/auth/email/verify") {
            jsonBody(TokenRequestBody(token))
        }.heliumEnsureSuccess()
    }

    /** Requests another verification mail. Response is identical for unknown addresses. */
    public suspend fun resendVerificationEmail(email: String): AcceptedResponse =
        call(HttpMethod.Post, "/v1/auth/email/resend") { jsonBody(EmailRequest(email)) }.heliumBody()

    /** Starts a password reset. Response is identical for unknown addresses. */
    public suspend fun requestPasswordReset(email: String): AcceptedResponse =
        call(HttpMethod.Post, "/v1/auth/password-reset/request") {
            jsonBody(EmailRequest(email))
        }.heliumBody()

    /**
     * Finishes a password reset with the token from the mail.
     *
     * No session is issued: a reset proves mailbox control, not identity. Send the user to the
     * sign-in screen afterwards.
     */
    public suspend fun completePasswordReset(token: String, newPassword: String) {
        call(HttpMethod.Post, "/v1/auth/password-reset/complete") {
            jsonBody(PasswordResetCompleteRequest(token, newPassword))
        }.heliumEnsureSuccess()
    }

    /** External providers the login UI may offer. */
    public suspend fun providers(): ProviderListResponse =
        call(HttpMethod.Get, "/v1/auth/providers").heliumBody()

    /**
     * The URL that starts an external-provider round trip.
     *
     * @param intent `false` signs in, `true` links the provider to the *already authenticated*
     *        account. Linking requires a session; HeliumID never links accounts by matching
     *        email addresses.
     */
    public fun providerStartUrl(provider: String, link: Boolean = false): String {
        val path = "$baseUrl/v1/auth/providers/${provider.encodeURLPathPart()}/start"
        return if (link) "$path?intent=link" else path
    }

    // --- /v1/me ------------------------------------------------------------------------

    /** The authenticated user's profile, roles and permissions. */
    public suspend fun me(): UserResponse = call(HttpMethod.Get, "/v1/me").heliumBody()

    /** Updates profile fields. `null` properties are left unchanged. */
    public suspend fun updateProfile(request: UpdateProfileRequest): UserResponse =
        call(HttpMethod.Put, "/v1/me") { jsonBody(request) }.heliumBody()

    /**
     * Changes the password.
     *
     * @throws HeliumApiException with [HeliumError.ReauthenticationRequired] if the session is
     *         too old, or [HeliumError.ValidationFailed] if the new password fails policy.
     */
    public suspend fun changePassword(currentPassword: String, newPassword: String) {
        call(HttpMethod.Put, "/v1/me/password") {
            jsonBody(ChangePasswordRequest(currentPassword, newPassword))
        }.heliumEnsureSuccess()
    }

    /** Starts an email change. Confirmation goes to the *new* address. */
    public suspend fun requestEmailChange(newEmail: String, currentPassword: String): AcceptedResponse =
        call(HttpMethod.Post, "/v1/me/email-change") {
            jsonBody(EmailChangeRequest(newEmail, currentPassword))
        }.heliumBody()

    /** Confirms an email change with the token sent to the new address. */
    public suspend fun confirmEmailChange(token: String) {
        call(HttpMethod.Post, "/v1/me/email-change/confirm") {
            jsonBody(TokenRequestBody(token))
        }.heliumEnsureSuccess()
    }

    /** Deletes the account. Irreversible. */
    public suspend fun deleteAccount(currentPassword: String? = null) {
        call(HttpMethod.Post, "/v1/me/delete") {
            jsonBody(DeleteAccountRequest(currentPassword))
        }.heliumEnsureSuccess()
    }

    /** Active sessions for the current user; exactly one has `current = true`. */
    public suspend fun sessions(): List<SessionResponse> =
        call(HttpMethod.Get, "/v1/me/sessions").heliumBody()

    /** Revokes one session. Revoking the current one signs this client out. */
    public suspend fun revokeSession(sessionId: String) {
        call(HttpMethod.Delete, "/v1/me/sessions/${sessionId.encodeURLPathPart()}").heliumEnsureSuccess()
    }

    /** MFA factors registered on the account. */
    public suspend fun mfaFactors(): List<MfaFactorResponse> =
        call(HttpMethod.Get, "/v1/me/mfa").heliumBody()

    /**
     * Begins TOTP enrollment.
     *
     * The response is the only place the secret ever appears. Show it, let the user scan it, and
     * discard it — do not persist, cache or log [TotpEnrollmentResponse.secret]. Enrollment is
     * not active until [confirmTotp] succeeds.
     */
    public suspend fun enrollTotp(): TotpEnrollmentResponse =
        call(HttpMethod.Post, "/v1/me/mfa/totp/enroll").heliumBody()

    /**
     * Activates a pending TOTP factor by proving the user can generate a code.
     *
     * @return recovery codes, shown once and never retrievable again.
     */
    public suspend fun confirmTotp(factorId: String, code: String): RecoveryCodesResponse =
        call(HttpMethod.Post, "/v1/me/mfa/totp/confirm") {
            jsonBody(TotpConfirmRequest(factorId, code))
        }.heliumBody()

    /** Removes a TOTP factor. Requires reauthentication. */
    public suspend fun disableTotp(factorId: String, currentPassword: String? = null) {
        call(HttpMethod.Post, "/v1/me/mfa/totp/disable") {
            jsonBody(TotpDisableRequest(factorId, currentPassword))
        }.heliumEnsureSuccess()
    }

    /** Replaces the recovery codes. The previous set stops working immediately. */
    public suspend fun regenerateRecoveryCodes(): RecoveryCodesResponse =
        call(HttpMethod.Post, "/v1/me/mfa/recovery-codes").heliumBody()

    /** External identities linked to the account. */
    public suspend fun linkedProviders(): List<LinkedProviderResponse> =
        call(HttpMethod.Get, "/v1/me/providers").heliumBody()

    /**
     * Unlinks an external identity.
     *
     * @throws HeliumApiException with [HeliumError.Conflict] and code `last_credential_removal`
     *         when this would leave the account with no way in.
     */
    public suspend fun unlinkProvider(provider: String) {
        call(HttpMethod.Delete, "/v1/me/providers/${provider.encodeURLPathPart()}").heliumEnsureSuccess()
    }

    // --- /v1/admin ---------------------------------------------------------------------

    /**
     * Searches users.
     *
     * @param term free-text match on username and email.
     * @param status one of the `UserStatus` names, e.g. `ACTIVE`.
     * @param limit clamped server-side to 1..200.
     */
    public suspend fun listUsers(
        term: String? = null,
        status: String? = null,
        role: String? = null,
        limit: Int = 50,
        offset: Long = 0,
    ): PageResponse<AdminUserResponse> = call(HttpMethod.Get, "/v1/admin/users") {
        term?.let { parameter("q", it) }
        status?.let { parameter("status", it) }
        role?.let { parameter("role", it) }
        parameter("limit", limit)
        parameter("offset", offset)
    }.heliumBody()

    /** One user, by id. */
    public suspend fun getUser(userId: String): AdminUserResponse =
        call(HttpMethod.Get, "/v1/admin/users/${userId.encodeURLPathPart()}").heliumBody()

    /** Sets a user's status, e.g. `SUSPENDED`. */
    public suspend fun updateUserStatus(userId: String, status: String) {
        call(HttpMethod.Put, "/v1/admin/users/${userId.encodeURLPathPart()}/status") {
            jsonBody(UpdateUserStatusRequest(status))
        }.heliumEnsureSuccess()
    }

    /** Replaces a user's roles with [roles]. Not additive. */
    public suspend fun assignRoles(userId: String, roles: List<String>) {
        call(HttpMethod.Put, "/v1/admin/users/${userId.encodeURLPathPart()}/roles") {
            jsonBody(AssignRolesRequest(roles))
        }.heliumEnsureSuccess()
    }

    /** Signs a user out everywhere. @return how many sessions were revoked. */
    public suspend fun revokeUserSessions(userId: String): Int =
        call(HttpMethod.Post, "/v1/admin/users/${userId.encodeURLPathPart()}/revoke-sessions")
            .heliumBody<RevokedSessionsResponse>()
            .revoked

    /** A user's active sessions. `current` is always `false` here — it is not your session. */
    public suspend fun userSessions(userId: String): List<SessionResponse> =
        call(HttpMethod.Get, "/v1/admin/users/${userId.encodeURLPathPart()}/sessions").heliumBody()

    /** Every role and the permissions it grants. */
    public suspend fun listRoles(): List<RoleResponse> =
        call(HttpMethod.Get, "/v1/admin/roles").heliumBody()

    /** Every permission the server recognises. Use it to build a role editor. */
    public suspend fun listPermissions(): List<String> =
        call(HttpMethod.Get, "/v1/admin/permissions").heliumBody()

    /**
     * Creates or replaces a role.
     *
     * @throws HeliumApiException with [HeliumError.Conflict] for a built-in role: code depends
     *         on those, and stripping `ADMINISTRATOR` would be a one-click lockout.
     */
    public suspend fun upsertRole(name: String, request: UpsertRoleRequest): RoleResponse =
        call(HttpMethod.Put, "/v1/admin/roles/${name.encodeURLPathPart()}") {
            jsonBody(request)
        }.heliumBody()

    /** Deletes a custom role. */
    public suspend fun deleteRole(name: String) {
        call(HttpMethod.Delete, "/v1/admin/roles/${name.encodeURLPathPart()}").heliumEnsureSuccess()
    }

    /** Registered OAuth clients. */
    public suspend fun listClients(limit: Int = 50, offset: Long = 0): PageResponse<ClientResponse> =
        call(HttpMethod.Get, "/v1/admin/clients") {
            parameter("limit", limit)
            parameter("offset", offset)
        }.heliumBody()

    /** One client, by id. */
    public suspend fun getClient(clientId: String): ClientResponse =
        call(HttpMethod.Get, "/v1/admin/clients/${clientId.encodeURLPathPart()}").heliumBody()

    /** Scopes the authorization server knows about. */
    public suspend fun listScopes(): List<ScopeResponse> =
        call(HttpMethod.Get, "/v1/admin/scopes").heliumBody()

    /**
     * Creates a scope or replaces its description and consent behaviour.
     *
     * Register the scopes your API needs before registering the client that requests them:
     * [registerClient] rejects any scope this catalogue does not contain.
     *
     * @param name lowercase, 3–64 characters from `a-z 0-9 : . _ -`. The colon is there for the
     *        conventional `resource:action` shape. Whitespace is rejected — the `scope` parameter
     *        is space-delimited, so a name with a space would split in two on the wire.
     * @throws HeliumApiException with [HeliumError.Conflict] for a built-in scope (`openid`,
     *         `profile`, `email`, `offline_access`), which the server will not let you edit.
     */
    public suspend fun upsertScope(name: String, request: UpsertScopeRequest): ScopeResponse =
        call(HttpMethod.Put, "/v1/admin/scopes/${name.encodeURLPathPart()}") {
            jsonBody(request)
        }.heliumBody()

    /**
     * Removes a scope from the catalogue.
     *
     * @throws HeliumApiException with [HeliumError.Conflict] when the scope is built in, or when
     *         a registered client still lists it — detach it from those clients first. Deleting
     *         it out from under them would strip the scope silently and only surface later as
     *         `invalid_scope` on an authorization request that used to work.
     */
    public suspend fun deleteScope(name: String) {
        call(HttpMethod.Delete, "/v1/admin/scopes/${name.encodeURLPathPart()}").heliumEnsureSuccess()
    }

    /**
     * Registers an OAuth client.
     *
     * @return the client id and, for confidential clients, the generated secret. This is the
     *         only response that will ever contain it — store it immediately.
     */
    public suspend fun registerClient(request: RegisterClientRequest): ClientSecretResponse =
        call(HttpMethod.Post, "/v1/admin/clients") { jsonBody(request) }.heliumBody()

    /** Updates a client. `null` properties are left unchanged. */
    public suspend fun updateClient(clientId: String, request: UpdateClientRequest) {
        call(HttpMethod.Patch, "/v1/admin/clients/${clientId.encodeURLPathPart()}") {
            jsonBody(request)
        }.heliumEnsureSuccess()
    }

    /**
     * Rotates a client secret.
     *
     * The previous secret stops working as soon as this returns, so deploy the new one before
     * rotating, or accept a window of failed client authentications.
     */
    public suspend fun rotateClientSecret(clientId: String): ClientSecretResponse =
        call(HttpMethod.Post, "/v1/admin/clients/${clientId.encodeURLPathPart()}/rotate-secret")
            .heliumBody()

    /** Deletes a client. Its tokens stop being accepted. */
    public suspend fun deleteClient(clientId: String) {
        call(HttpMethod.Delete, "/v1/admin/clients/${clientId.encodeURLPathPart()}").heliumEnsureSuccess()
    }

    /**
     * Queries the audit log.
     *
     * @param userId filters on the *subject* of the event, not the actor.
     * @param limit clamped server-side to 1..500.
     */
    public suspend fun audit(
        userId: String? = null,
        eventType: String? = null,
        limit: Int = 100,
        offset: Long = 0,
    ): PageResponse<AuditRecordResponse> = call(HttpMethod.Get, "/v1/admin/audit") {
        userId?.let { parameter("user_id", it) }
        eventType?.let { parameter("event_type", it) }
        parameter("limit", limit)
        parameter("offset", offset)
    }.heliumBody()

    // --- plumbing ----------------------------------------------------------------------

    /**
     * One request, with credentials attached and transport failures normalised.
     *
     * `CancellationException` is rethrown untouched: swallowing it would break structured
     * concurrency and leave a coroutine looking like it completed normally.
     */
    private suspend fun call(
        method: HttpMethod,
        path: String,
        configure: HeliumRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        val bearer = bearerToken?.invoke()
        val csrf = if (method.isStateChanging()) csrfToken?.invoke() else null
        return try {
            http.request("$baseUrl$path") {
                this.method = method
                bearer?.let { header(HttpHeaders.Authorization, "Bearer $it") }
                csrf?.let { header(CSRF_HEADER, it) }
                configure()
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            // The message never includes the URL's query string or any header, so a token that
            // rode in a request cannot reappear in a log line about its failure.
            throw HeliumTransportException("Could not reach the identity server at $baseUrl", failure)
        }
    }

    /** Shared body for the three token grants, including client authentication. */
    private suspend fun tokenRequest(
        clientId: String,
        clientSecret: String?,
        form: FormBuilder.() -> Unit,
    ): TokenEndpointResponse = call(HttpMethod.Post, "/oauth2/token") {
        clientAuth(clientId, clientSecret)
        setBody(
            FormDataContent(
                parameters {
                    form()
                    // Public clients identify themselves in the body; confidential ones already
                    // did so in the Authorization header.
                    if (clientSecret == null) append("client_id", clientId)
                },
            ),
        )
    }.heliumBody()
}

private fun normalizeBaseUrl(baseUrl: String): String {
    require(baseUrl.startsWith("http://") || baseUrl.startsWith("https://")) {
        "baseUrl must be an absolute http(s) URL"
    }
    return baseUrl.trimEnd('/')
}

/**
 * Derives a client that speaks JSON and gives up in bounded time.
 *
 * `expectSuccess = false` is required, not a preference: the SDK reads the error body itself to
 * build a typed [HeliumError], and Ktor throwing first would destroy that information.
 */
private fun HttpClient.withHeliumDefaults(
    settings: HeliumIdClientConfig = HeliumIdClientConfig(),
): HttpClient = config {
    install(ContentNegotiation) { json(HeliumJson) }
    install(HttpTimeout) {
        requestTimeoutMillis = settings.requestTimeout.inWholeMilliseconds
        connectTimeoutMillis = settings.connectTimeout.inWholeMilliseconds
        socketTimeoutMillis = settings.socketTimeout.inWholeMilliseconds
    }
    expectSuccess = false
}

/** Alias so the request lambdas above read as intent rather than as Ktor plumbing. */
private typealias HeliumRequestBuilder = io.ktor.client.request.HttpRequestBuilder

/** Alias for the `parameters { }` receiver used to build form bodies. */
private typealias FormBuilder = io.ktor.http.ParametersBuilder

/** Attaches `client_secret_basic` credentials when the client is confidential. */
private fun HeliumRequestBuilder.clientAuth(clientId: String, clientSecret: String?) {
    if (clientSecret == null) return
    // RFC 6749 §2.3.1: both halves are form-urlencoded before base64. Implementations that skip
    // this fail on any secret containing `+`, `%` or a space.
    val credentials = "${clientId.encodeURLParameter()}:${clientSecret.encodeURLParameter()}"
    header(
        HttpHeaders.Authorization,
        "Basic " + Base64.getEncoder().encodeToString(credentials.toByteArray(Charsets.UTF_8)),
    )
}

/** Sets a JSON request body with the right content type. */
private fun HeliumRequestBuilder.jsonBody(body: Any) {
    contentType(ContentType.Application.Json)
    setBody(body)
}

private fun HttpMethod.isStateChanging(): Boolean =
    this != HttpMethod.Get && this != HttpMethod.Head && this != HttpMethod.Options

/**
 * Header carrying the double-submit CSRF token for cookie-authenticated state changes.
 *
 * Bearer-authenticated requests are exempt server-side and the SDK does not send it for them.
 */
public const val CSRF_HEADER: String = "X-CSRF-Token"

/**
 * Configuration for [HeliumIdClient.create].
 *
 * Every value has a working default; supply only what differs.
 */
public class HeliumIdClientConfig {

    /**
     * Use this engine instead of the bundled CIO one.
     *
     * Set it when you need cookie support (for the browser-session endpoints), a proxy, mTLS,
     * or simply to share one engine across your application. When set, [HeliumIdClient.close]
     * will not shut it down — its lifecycle stays yours.
     */
    public var httpClient: HttpClient? = null

    /**
     * Total budget for a request, including retries inside the engine.
     *
     * Kept short deliberately: an identity call that has not answered in ten seconds is not
     * going to, and a request thread parked on it is a request thread not serving users.
     */
    public var requestTimeout: Duration = 10.seconds

    /** TCP connect budget. */
    public var connectTimeout: Duration = 5.seconds

    /** Idle-socket budget between bytes. */
    public var socketTimeout: Duration = 10.seconds

    internal var bearerTokenProvider: (suspend () -> String?)? = null
        private set

    internal var csrfTokenProvider: (suspend () -> String?)? = null
        private set

    /**
     * Supplies the access token for every request.
     *
     * Called per request, so it can refresh transparently. Return `null` to send no
     * `Authorization` header at all — useful when the same client also serves anonymous
     * endpoints like registration.
     *
     * The token is never logged and never stored by the SDK.
     */
    public fun bearerToken(provider: suspend () -> String?) {
        bearerTokenProvider = provider
    }

    /**
     * Supplies the double-submit CSRF token for cookie-authenticated state changes.
     *
     * Obtain it from [HeliumIdClient.session] and re-read it after every authentication: the
     * server issues a fresh token on sign-in so a value captured beforehand is useless
     * afterwards.
     */
    public fun csrfToken(provider: suspend () -> String?) {
        csrfTokenProvider = provider
    }
}
