package dev.kamiql.helium.app

import dev.kamiql.helium.domain.client.ClientType
import dev.kamiql.helium.domain.client.GrantType
import dev.kamiql.helium.domain.client.OAuthClient
import dev.kamiql.helium.domain.common.ClientId
import dev.kamiql.helium.domain.common.EmailAddress
import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.common.Username
import dev.kamiql.helium.domain.policy.Role
import dev.kamiql.helium.domain.user.User
import dev.kamiql.helium.domain.user.UserStatus
import org.slf4j.LoggerFactory

/**
 * Development-only seeding.
 *
 * Creates an administrator and a demo SPA client so a fresh database is usable immediately.
 * Guarded three ways, because a bootstrap admin reaching production would be catastrophic:
 *
 *  1. [HeliumConfig.fromEnvironment] only reads the bootstrap variables outside production;
 *  2. [HeliumConfig.validate] refuses to start if they are set with `HELIUM_ENV=prod`;
 *  3. [run] checks the environment again here.
 *
 * It is deliberately **not** a migration. A migration runs everywhere, including production,
 * and would put a credential in source control (see the note in `V2__reference_data.sql`).
 */
class DevBootstrap(
    private val components: HeliumComponents,
    private val config: HeliumConfig,
) {

    private val log = LoggerFactory.getLogger(DevBootstrap::class.java)

    suspend fun run() {
        if (config.environment.isProduction) {
            log.error("dev bootstrap invoked in production; refusing")
            return
        }

        bootstrapAdmin()
        bootstrapDemoClient()
    }

    private suspend fun bootstrapAdmin() {
        val admin = config.bootstrapAdmin ?: return
        val username = Username.parse(admin.username) ?: run {
            log.warn("HELIUM_BOOTSTRAP_ADMIN_USERNAME is not a valid username; skipping")
            return
        }
        val email = EmailAddress.parse(admin.email) ?: run {
            log.warn("HELIUM_BOOTSTRAP_ADMIN_EMAIL is not a valid address; skipping")
            return
        }

        if (components.users.findByUsername(username) != null || components.users.findByEmail(email) != null) {
            log.info("bootstrap administrator already exists")
            return
        }

        val now = components.clock.now()
        val user = User(
            id = UserId.random(),
            username = username,
            primaryEmail = email,
            firstName = "Bootstrap",
            lastName = "Administrator",
            // Pre-verified: there is no mail server in a fresh dev stack until Mailpit is up,
            // and an admin who cannot sign in is not a useful bootstrap.
            status = UserStatus.ACTIVE,
            emailVerifiedAt = now,
            createdAt = now,
            updatedAt = now,
            version = 0,
        )
        components.users.insert(user)
        components.credentials.upsert(
            userId = user.id,
            hash = components.passwordHasherForBootstrap().hash(admin.password),
            at = now,
        )
        components.roles.assign(user.id, setOf(Role.ADMINISTRATOR, Role.USER))

        log.warn(
            "created bootstrap administrator '{}' — development only, never enable this in production",
            username.display,
        )
    }

    /**
     * A public SPA client for the bundled frontend.
     *
     * Public with PKCE and no secret, because the frontend is a browser application and a
     * secret embedded in one is not a secret. `skipConsent` is on: it is first-party.
     */
    private suspend fun bootstrapDemoClient() {
        val clientId = ClientId("helium-console")
        if (components.clients.findById(clientId) != null) return

        val now = components.clock.now()
        val base = config.publicBaseUrl.trimEnd('/')
        components.clients.insert(
            OAuthClient(
                clientId = clientId,
                name = "HeliumID Console",
                type = ClientType.PUBLIC,
                secretHash = null,
                secretRotatedAt = null,
                redirectUris = setOf("$base/callback", "$base/oauth/callback"),
                allowedScopes = setOf("openid", "profile", "email", "offline_access"),
                allowedGrantTypes = setOf(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN),
                skipConsent = true,
                audiences = setOf("helium-console"),
                enabled = true,
                createdAt = now,
                updatedAt = now,
            ),
        )
        log.info("created development OAuth client '{}'", clientId.value)
    }
}
