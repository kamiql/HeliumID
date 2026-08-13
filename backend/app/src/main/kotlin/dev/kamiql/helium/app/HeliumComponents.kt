package dev.kamiql.helium.app

import dev.kamiql.helium.api.AuditQueryPort
import dev.kamiql.helium.api.AuditRecordResponse
import dev.kamiql.helium.api.HeliumApiDependencies
import dev.kamiql.helium.api.HttpSecurityConfig
import dev.kamiql.helium.api.PrincipalResolver
import dev.kamiql.helium.audit.ScrubbedAuditPort
import dev.kamiql.helium.crypto.AesGcmSecretCipher
import dev.kamiql.helium.crypto.Argon2idPasswordHasher
import dev.kamiql.helium.crypto.HmacTokenHasher
import dev.kamiql.helium.crypto.LocalKeyProvider
import dev.kamiql.helium.crypto.SecureRandomSource
import dev.kamiql.helium.domain.credential.BreachedPasswordChecker
import dev.kamiql.helium.domain.credential.PasswordPolicy
import dev.kamiql.helium.domain.crypto.HeliumClock
import dev.kamiql.helium.domain.repository.Page
import dev.kamiql.helium.flow.FlowRunner
import dev.kamiql.helium.flow.port.MetricsPort
import dev.kamiql.helium.flow.port.RateLimiter
import dev.kamiql.helium.flow.port.SecurityTransactionStore
import dev.kamiql.helium.identity.AdminFlows
import dev.kamiql.helium.identity.IdentityFlows
import dev.kamiql.helium.identity.MfaFlows
import dev.kamiql.helium.identity.PasswordPolicyService
import dev.kamiql.helium.identity.ProviderFlows
import dev.kamiql.helium.identity.SessionService
import dev.kamiql.helium.identity.TrustedDeviceService
import dev.kamiql.helium.identity.VerificationTokenService
import dev.kamiql.helium.jobs.LoggingMailSender
import dev.kamiql.helium.jobs.MailConfig
import dev.kamiql.helium.jobs.MailOutboxHandler
import dev.kamiql.helium.jobs.MaintenanceJobs
import dev.kamiql.helium.jobs.OutboxDispatcher
import dev.kamiql.helium.jobs.SigningKeyRotation
import dev.kamiql.helium.jobs.SmtpMailSender
import dev.kamiql.helium.mfa.RecoveryCodeMfaMethod
import dev.kamiql.helium.mfa.TotpMfaMethod
import dev.kamiql.helium.mfa.webauthn.WebAuthnMfaMethod
import dev.kamiql.helium.oauth.ClientAdminFlows
import dev.kamiql.helium.oauth.OAuthFlows
import dev.kamiql.helium.oauth.SigningKeyService
import dev.kamiql.helium.oauth.TokenIssuer
import dev.kamiql.helium.persistence.DatabaseConfig
import dev.kamiql.helium.persistence.ExposedTransactionManager
import dev.kamiql.helium.persistence.HeliumDatabase
import dev.kamiql.helium.persistence.repository.AuditQueryRepository
import dev.kamiql.helium.persistence.repository.AuditRepositoryImpl
import dev.kamiql.helium.persistence.repository.AuthorizationCodeRepositoryImpl
import dev.kamiql.helium.persistence.repository.ClientRepositoryImpl
import dev.kamiql.helium.persistence.repository.ConsentRepositoryImpl
import dev.kamiql.helium.persistence.repository.ExternalIdentityRepositoryImpl
import dev.kamiql.helium.persistence.repository.IdempotencyStoreImpl
import dev.kamiql.helium.persistence.repository.MfaRepositoryImpl
import dev.kamiql.helium.persistence.repository.OutboxDispatchRepository
import dev.kamiql.helium.persistence.repository.OutboxRepositoryImpl
import dev.kamiql.helium.persistence.repository.PasswordCredentialRepositoryImpl
import dev.kamiql.helium.persistence.repository.RefreshTokenRepositoryImpl
import dev.kamiql.helium.persistence.repository.RevokedTokenRepositoryImpl
import dev.kamiql.helium.persistence.repository.RoleRepositoryImpl
import dev.kamiql.helium.persistence.repository.SessionRepositoryImpl
import dev.kamiql.helium.persistence.repository.TrustedDeviceRepositoryImpl
import dev.kamiql.helium.persistence.repository.SigningKeyRepositoryImpl
import dev.kamiql.helium.persistence.repository.UserRepositoryImpl
import dev.kamiql.helium.persistence.repository.VerificationTokenRepositoryImpl
import dev.kamiql.helium.persistence.repository.WebAuthnCredentialRepositoryImpl
import dev.kamiql.helium.provider.oidc.discordProvider
import dev.kamiql.helium.provider.oidc.gitHubProvider
import dev.kamiql.helium.provider.oidc.OidcIdentityProvider
import dev.kamiql.helium.provider.oidc.OidcProviderConfig
import dev.kamiql.helium.redis.InMemoryRateLimiter
import dev.kamiql.helium.redis.InMemorySecurityTransactionStore
import dev.kamiql.helium.redis.RedisRateLimiter
import dev.kamiql.helium.redis.RedisSecurityTransactionStore
import dev.kamiql.helium.spi.ExternalIdentityProvider
import dev.kamiql.helium.spi.MfaMethodRegistry
import dev.kamiql.helium.spi.ProviderRegistry
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import io.lettuce.core.RedisClient
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory

/**
 * Constructs the object graph.
 *
 * Written by hand rather than with a DI container. The wiring is the one place where every
 * security-relevant choice becomes concrete — which cipher, which limiter, which key provider —
 * and an explicit constructor call is far easier to review than a set of module declarations
 * resolved at runtime. CLAUDE.md's warning about reflection-heavy magic in the security core
 * applies here too.
 *
 * Closing this closes the database pool and the Redis client.
 */
class HeliumComponents(private val config: HeliumConfig) : AutoCloseable {

    private val log = LoggerFactory.getLogger(HeliumComponents::class.java)

    val clock: HeliumClock = HeliumClock.SYSTEM

    // --- infrastructure -------------------------------------------------------

    val database: HeliumDatabase = HeliumDatabase.connect(
        DatabaseConfig(
            jdbcUrl = config.database.jdbcUrl,
            username = config.database.username,
            password = config.database.password,
            maxPoolSize = config.database.maxPoolSize,
            migrateOnStart = config.database.migrateOnStart,
        ),
    )

    private val redisClient: RedisClient? = config.redisUrl?.let(RedisClient::create)
    private val redisCommands = redisClient?.connect()?.async()

    // --- cryptography ----------------------------------------------------------

    val random = SecureRandomSource()

    private val keyProvider = LocalKeyProvider.fromBase64(
        dataKeysBase64 = config.dataKeysBase64,
        currentVersion = config.dataKeyVersion,
        tokenHmacKeyBase64 = config.tokenHmacKeyBase64,
        pepperBase64 = config.passwordPepperBase64,
        pepperVersion = config.passwordPepperVersion,
    )

    val tokenHasher = HmacTokenHasher(keyProvider)
    private val cipher = AesGcmSecretCipher(keyProvider, random)

    private val passwordHasher = Argon2idPasswordHasher(
        parameters = config.argon2,
        random = random,
        keyProvider = keyProvider,
        parallelismLimit = config.argon2Parallelism,
    )

    // --- repositories -----------------------------------------------------------

    private val db = database.database

    val users = UserRepositoryImpl(db)
    val credentials = PasswordCredentialRepositoryImpl(db)
    val roles = RoleRepositoryImpl(db)
    val sessions = SessionRepositoryImpl(db)
    val trustedDeviceRepository = TrustedDeviceRepositoryImpl(db)
    val identities = ExternalIdentityRepositoryImpl(db)
    val mfaRepository = MfaRepositoryImpl(db)
    val webAuthnCredentials = WebAuthnCredentialRepositoryImpl(db)
    val verificationTokens = VerificationTokenRepositoryImpl(db)
    val refreshTokens = RefreshTokenRepositoryImpl(db)
    val authorizationCodes = AuthorizationCodeRepositoryImpl(db)
    val revokedTokens = RevokedTokenRepositoryImpl(db)
    val clients = ClientRepositoryImpl(db)
    val consents = ConsentRepositoryImpl(db)
    val signingKeyRepository = SigningKeyRepositoryImpl(db)
    private val auditRepository = AuditRepositoryImpl(db)
    private val outboxRepository = OutboxRepositoryImpl(db)
    private val auditQueryRepository = AuditQueryRepository(db)
    val idempotencyStore = IdempotencyStoreImpl(db)
    private val outboxDispatchRepository = OutboxDispatchRepository(db)

    // --- ephemeral state --------------------------------------------------------

    /**
     * Redis where configured, in-memory otherwise.
     *
     * The in-memory limiter is correct only on a single instance, which is why
     * [HeliumConfig.validate] refuses to start production without Redis.
     */
    val rateLimiter: RateLimiter = redisCommands
        ?.let { RedisRateLimiter(it, failClosed = true) }
        ?: InMemoryRateLimiter().also {
            log.warn("no Redis configured; rate limiting is per-instance and will not hold across replicas")
        }

    val transactionStore: SecurityTransactionStore = redisCommands
        ?.let { RedisSecurityTransactionStore(it) }
        ?: InMemorySecurityTransactionStore().also {
            log.warn("no Redis configured; MFA and provider transactions are per-instance")
        }

    // --- services ---------------------------------------------------------------

    private val transactionManager = ExposedTransactionManager(db)

    val flowRunner = FlowRunner(
        transactionManager = transactionManager,
        outbox = outboxRepository,
        // Wrapped, not used directly. Audit metadata is assembled from flow state, so what reaches
        // the permanent table depends on every call site remembering to mark a key sensitive. The
        // decorator is the backstop for the one that forgets: WebAuthn pushes credential ids,
        // public keys, challenges and signatures through flow state as ordinary strings.
        audit = ScrubbedAuditPort(auditRepository),
        metrics = MetricsPort.NoOp,
    )

    val sessionService = SessionService(sessions, random, tokenHasher, config.lifetimes)

    val trustedDeviceService = TrustedDeviceService(
        devices = trustedDeviceRepository,
        random = random,
        tokenHasher = tokenHasher,
        lifetimes = config.lifetimes,
        // Reuse detection has to survive the challenge that unwinds the login transaction, so
        // the service needs its own transaction and its own path to the outbox.
        transactionManager = transactionManager,
        outbox = outboxRepository,
    )

    private val verificationTokenService =
        VerificationTokenService(verificationTokens, random, tokenHasher, config.lifetimes)

    val passwordPolicyService = PasswordPolicyService(
        policy = PasswordPolicy.DEFAULT,
        // A breach checker is a network dependency; wiring one is a deployment decision.
        // Disabled means the length policy carries the weight, which is documented in the README.
        breachedChecker = BreachedPasswordChecker.Disabled,
    )

    val signingKeys = SigningKeyService(signingKeyRepository, cipher)

    val tokenIssuer = TokenIssuer(config.issuerUrl, signingKeys, random, config.lifetimes)

    // --- MFA ---------------------------------------------------------------------

    private val totpMethod = TotpMfaMethod(
        mfaRepository = mfaRepository,
        users = users,
        cipher = cipher,
        random = random,
        issuerLabel = "HeliumID",
    )

    private val recoveryCodeMethod = RecoveryCodeMfaMethod(mfaRepository, tokenHasher, random)

    /**
     * Passkeys as a second factor.
     *
     * The relying party comes from configuration and nowhere else: origin and RP-ID binding is the
     * entire phishing-resistance property, so a value derived from a request header would hand an
     * attacker the ability to name their own origin. [HeliumConfig.validate] refuses to start if
     * an origin does not sit under the RP ID.
     */
    private val webAuthnMethod = WebAuthnMfaMethod(
        mfaRepository = mfaRepository,
        credentials = webAuthnCredentials,
        users = users,
        transactions = transactionStore,
        random = random,
        relyingParty = config.webAuthn,
    )

    private val mfaMethods = MfaMethodRegistry(listOf(totpMethod, recoveryCodeMethod, webAuthnMethod))

    // --- external providers ---------------------------------------------------------

    /**
     * HTTP client for outbound provider calls.
     *
     * Redirects are **not** followed: a provider that redirects a token exchange is either
     * misconfigured or being impersonated, and following it would send our client secret to
     * wherever the redirect points (concept §4.9).
     */
    private val providerHttpClient = HttpClient(CIO) {
        followRedirects = false
        expectSuccess = false
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
        install(HttpTimeout) {
            requestTimeoutMillis = 10_000
            connectTimeoutMillis = 5_000
            socketTimeoutMillis = 10_000
        }
    }

    /**
     * The configured providers, and only those.
     *
     * Built from configuration rather than from a database table: concept §4.9 requires a fixed
     * provider registry, because a registry an attacker (or a compromised administrator) can edit
     * is an SSRF primitive pointed at whatever internal endpoint they choose.
     *
     * Google speaks OIDC and gets the standards-based adapter, which verifies a signed ID token.
     * GitHub and Discord do not, so they get the API adapter — weaker, and deliberately a
     * different class so nobody mistakes an authenticated API response for a signed assertion.
     */
    val providers = ProviderRegistry(
        buildList<ExternalIdentityProvider> {
            config.google?.let { credentials ->
                add(
                    OidcIdentityProvider(
                        config = OidcProviderConfig.google(credentials.clientId, credentials.clientSecret),
                        httpClient = providerHttpClient,
                        random = random,
                    ),
                )
            }
            config.github?.let { credentials ->
                add(gitHubProvider(credentials.clientId, credentials.clientSecret, providerHttpClient, random))
            }
            config.discord?.let { credentials ->
                add(discordProvider(credentials.clientId, credentials.clientSecret, providerHttpClient, random))
            }
        },
    ).also { registry ->
        log.info(
            "external identity providers enabled: {}",
            registry.available.map { it.value }.sorted().ifEmpty { listOf("none") },
        )
    }

    // --- flows -----------------------------------------------------------------------

    val identityFlows = IdentityFlows(
        users = users,
        credentials = credentials,
        sessions = sessions,
        roles = roles,
        refreshTokens = refreshTokens,
        passwordHasher = passwordHasher,
        passwordPolicy = passwordPolicyService,
        sessionService = sessionService,
        trustedDevices = trustedDeviceService,
        verificationTokens = verificationTokenService,
        transactions = transactionStore,
        mfaMethods = mfaMethods,
        rateLimiter = rateLimiter,
        random = random,
        lifetimes = config.lifetimes,
        mfaPolicy = config.mfaPolicy,
    )

    val mfaFlows = MfaFlows(
        users = users,
        credentials = credentials,
        sessions = sessions,
        mfaRepository = mfaRepository,
        mfaMethods = mfaMethods,
        recoveryCodes = recoveryCodeMethod,
        passwordHasher = passwordHasher,
        rateLimiter = rateLimiter,
        trustedDevices = trustedDeviceService,
        lifetimes = config.lifetimes,
    )

    val adminFlows =
        AdminFlows(users, roles, sessions, refreshTokens, trustedDeviceService, config.lifetimes)

    val providerFlows = ProviderFlows(
        users = users,
        identities = identities,
        credentials = credentials,
        mfaRepository = mfaRepository,
        sessions = sessions,
        providers = providers,
        sessionService = sessionService,
        transactions = transactionStore,
        rateLimiter = rateLimiter,
        random = random,
        lifetimes = config.lifetimes,
    )

    val oauthFlows = OAuthFlows(
        issuerUrl = config.issuerUrl,
        clients = clients,
        users = users,
        sessions = sessions,
        consents = consents,
        codes = authorizationCodes,
        refreshTokens = refreshTokens,
        revokedTokens = revokedTokens,
        tokenIssuer = tokenIssuer,
        tokenHasher = tokenHasher,
        random = random,
        rateLimiter = rateLimiter,
        transactionManager = transactionManager,
        outbox = outboxRepository,
        lifetimes = config.lifetimes,
    )

    val clientAdminFlows = ClientAdminFlows(
        clients = clients,
        users = users,
        sessions = sessions,
        tokenHasher = tokenHasher,
        random = random,
        // Loopback HTTP redirect URIs are only tolerable while developing locally.
        allowInsecureRedirects = !config.environment.isProduction,
        lifetimes = config.lifetimes,
    )

    // --- HTTP -------------------------------------------------------------------------

    val httpSecurity = HttpSecurityConfig(
        issuerUrl = config.issuerUrl,
        allowedOrigins = config.allowedOrigins,
        secureCookies = config.secureCookies,
        sameSite = config.sameSite,
        trustForwardedHeaders = config.trustForwardedHeaders,
    )

    private val principalResolver = PrincipalResolver(
        config = httpSecurity,
        sessionService = sessionService,
        users = users,
        roles = roles,
        tokenIssuer = tokenIssuer,
        revokedTokens = revokedTokens,
    )

    private val auditQueryPort = object : AuditQueryPort {
        override suspend fun query(
            subjectUserId: dev.kamiql.helium.domain.common.UserId?,
            eventType: String?,
            limit: Int,
            offset: Long,
        ): Page<AuditRecordResponse> {
            val page = auditQueryRepository.query(subjectUserId, eventType, limit, offset)
            return Page(
                items = page.items.map { record ->
                    AuditRecordResponse(
                        id = record.id.toString(),
                        eventType = record.eventType,
                        outcome = record.outcome.name,
                        actorUserId = record.actorUserId?.value?.toString(),
                        subjectUserId = record.subjectUserId?.value?.toString(),
                        clientId = record.clientId?.value,
                        requestId = record.requestId.value,
                        metadata = record.metadata,
                        createdAt = record.createdAt.toString(),
                    )
                },
                total = page.total,
                limit = page.limit,
                offset = page.offset,
            )
        }
    }

    val apiDependencies = HeliumApiDependencies(
        config = httpSecurity,
        clock = clock,
        random = random,
        flowRunner = flowRunner,
        principals = principalResolver,
        identityFlows = identityFlows,
        mfaFlows = mfaFlows,
        adminFlows = adminFlows,
        providerFlows = providerFlows,
        oauthFlows = oauthFlows,
        clientAdminFlows = clientAdminFlows,
        users = users,
        sessions = sessions,
        roles = roles,
        clients = clients,
        consents = consents,
        identities = identities,
        mfaRepository = mfaRepository,
        authorizationCodes = authorizationCodes,
        trustedDevices = trustedDeviceService,
        tokenIssuer = tokenIssuer,
        signingKeys = signingKeys,
        passwordPolicy = passwordPolicyService,
        providers = providers,
        auditQuery = auditQueryPort,
    )

    // --- background work ----------------------------------------------------------------

    private val mailConfig = MailConfig(
        host = config.mail?.host ?: "localhost",
        port = config.mail?.port ?: 25,
        username = config.mail?.username,
        password = config.mail?.password,
        fromAddress = config.mail?.from ?: "no-reply@localhost",
        fromName = config.mail?.fromName ?: "HeliumID",
        startTls = config.mail?.startTls ?: false,
        baseUrl = config.publicBaseUrl,
    )

    private val mailSender = if (config.mail != null) SmtpMailSender(mailConfig) else LoggingMailSender()

    val outboxDispatcher = OutboxDispatcher(
        repository = outboxDispatchRepository,
        handlers = listOf(MailOutboxHandler(users, mailSender, mailConfig)),
        clock = clock,
    )

    val maintenanceJobs = MaintenanceJobs(
        clock = clock,
        sessions = sessions,
        trustedDevices = trustedDeviceRepository,
        verificationTokens = verificationTokens,
        authorizationCodes = authorizationCodes,
        refreshTokens = refreshTokens,
        revokedTokens = revokedTokens,
        idempotency = idempotencyStore,
        outbox = outboxDispatchRepository,
        signingKeyRotation = SigningKeyRotation(signingKeys, signingKeyRepository),
    )

    /**
     * The password hasher, exposed only for the development bootstrap.
     *
     * Everything else reaches it through a flow; this is the single caller that legitimately
     * needs to create a credential outside one.
     */
    internal fun passwordHasherForBootstrap(): dev.kamiql.helium.domain.credential.PasswordHasher = passwordHasher

    /** Cheap liveness probe for `/health/ready`. */
    suspend fun isReady(): Boolean = runCatching { users.findByLoginIdentifier("__readiness__") }.isSuccess

    /** Ensures a signing key exists before the first token request arrives. */
    suspend fun warmUp() {
        signingKeys.activeSigningKey(clock.now())
    }

    override fun close() {
        providerHttpClient.close()
        redisClient?.shutdown()
        database.close()
    }
}
