package dev.kamiql.helium.jobs

import dev.kamiql.helium.domain.common.UserId
import dev.kamiql.helium.domain.repository.UserRepository
import jakarta.mail.Authenticator
import jakarta.mail.Message
import jakarta.mail.PasswordAuthentication
import jakarta.mail.Session
import jakarta.mail.Transport
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.util.Properties

/**
 * SMTP settings.
 *
 * @param baseUrl the public URL users click through to; the links in every mail are built from
 *        it. It is configuration, never derived from a request header, because a
 *        `Host`-derived link is a password-reset link an attacker can point at their own
 *        server.
 */
data class MailConfig(
    val host: String,
    val port: Int,
    val username: String?,
    val password: String?,
    val fromAddress: String,
    val fromName: String = "HeliumID",
    val startTls: Boolean = true,
    val baseUrl: String,
    val connectTimeoutMs: Int = 10_000,
    val readTimeoutMs: Int = 10_000,
)

/** Sends mail. A port so tests can assert on messages without an SMTP server. */
interface MailSender {
    suspend fun send(to: String, subject: String, htmlBody: String, textBody: String)
}

/** Jakarta Mail over SMTP. */
class SmtpMailSender(private val config: MailConfig) : MailSender {

    private val log = LoggerFactory.getLogger(SmtpMailSender::class.java)

    private val session: Session by lazy {
        val properties = Properties().apply {
            put("mail.smtp.host", config.host)
            put("mail.smtp.port", config.port.toString())
            put("mail.smtp.auth", (config.username != null).toString())
            put("mail.smtp.starttls.enable", config.startTls.toString())
            // Without this, StartTLS silently downgrades to plaintext when the server does not
            // advertise it, which would put verification links on the wire in clear.
            put("mail.smtp.starttls.required", config.startTls.toString())
            put("mail.smtp.connectiontimeout", config.connectTimeoutMs.toString())
            put("mail.smtp.timeout", config.readTimeoutMs.toString())
            put("mail.smtp.writetimeout", config.readTimeoutMs.toString())
        }
        if (config.username != null && config.password != null) {
            Session.getInstance(
                properties,
                object : Authenticator() {
                    override fun getPasswordAuthentication() =
                        PasswordAuthentication(config.username, config.password)
                },
            )
        } else {
            Session.getInstance(properties)
        }
    }

    override suspend fun send(to: String, subject: String, htmlBody: String, textBody: String) {
        withContext(Dispatchers.IO) {
            val message = MimeMessage(session).apply {
                setFrom(InternetAddress(config.fromAddress, config.fromName))
                setRecipients(Message.RecipientType.TO, InternetAddress.parse(to))
                setSubject(subject, "UTF-8")
                val multipart = jakarta.mail.internet.MimeMultipart("alternative")
                multipart.addBodyPart(
                    jakarta.mail.internet.MimeBodyPart().apply { setText(textBody, "UTF-8", "plain") },
                )
                multipart.addBodyPart(
                    jakarta.mail.internet.MimeBodyPart().apply { setText(htmlBody, "UTF-8", "html") },
                )
                setContent(multipart)
            }
            Transport.send(message)
            // Recipient is logged; the token in the body never is.
            log.info("sent '{}' mail", subject)
        }
    }
}

/** Discards everything. Used when no SMTP server is configured, so dev does not crash. */
class LoggingMailSender : MailSender {
    private val log = LoggerFactory.getLogger(LoggingMailSender::class.java)

    override suspend fun send(to: String, subject: String, htmlBody: String, textBody: String) {
        // The body carries one-time tokens, so only the subject is logged.
        log.warn("no SMTP configured; dropping '{}' mail", subject)
    }
}

/**
 * Turns identity events into transactional mail.
 *
 * Every mail this sends is either something the user asked for or a security notification they
 * need. Concept §4.10 lists the notification-worthy events; they are all here.
 */
class MailOutboxHandler(
    private val users: UserRepository,
    private val mail: MailSender,
    private val config: MailConfig,
) : OutboxHandler {

    private val log = LoggerFactory.getLogger(MailOutboxHandler::class.java)

    override val eventTypes: Set<String> = setOf(
        "user.email-verification-requested",
        "user.password-reset-requested",
        "user.password-changed",
        "user.email-changed",
        "auth.login-succeeded",
        "mfa.enabled",
        "mfa.enrolled",
        "mfa.disabled",
        "mfa.recovery-code-used",
        "identity.provider-linked",
        "identity.provider-unlinked",
        "token.refresh-reuse-detected",
    )

    override suspend fun handle(event: OutboxEventPayload) {
        val userId = event.fields["user_id"]?.let(UserId::parse) ?: return
        val user = users.findById(userId) ?: return
        val recipient = user.primaryEmail.display
        val name = user.displayName

        when (event.eventType) {
            "user.email-verification-requested" -> {
                val token = event.fields["token_id"] ?: return
                val purpose = event.fields["purpose"]
                val path = if (purpose == "email_change") "/account/email-change/confirm" else "/verify-email"
                val link = "${config.baseUrl.trimEnd('/')}$path?token=$token"
                mail.send(
                    to = recipient,
                    subject = "Confirm your email address",
                    htmlBody = template(
                        name,
                        "Confirm your email address",
                        "Use the link below to confirm this address. It expires in 24 hours.",
                        link to "Confirm email address",
                    ),
                    textBody = "Hi $name,\n\nConfirm your email address:\n$link\n\nThis link expires in 24 hours.",
                )
            }

            "user.password-reset-requested" -> {
                val token = event.fields["token_id"] ?: return
                val link = "${config.baseUrl.trimEnd('/')}/reset-password?token=$token"
                mail.send(
                    to = recipient,
                    subject = "Reset your password",
                    htmlBody = template(
                        name,
                        "Reset your password",
                        "Use the link below to set a new password. It expires in 15 minutes. " +
                            "If you did not request this, you can ignore this message — nothing has changed.",
                        link to "Set a new password",
                    ),
                    textBody = "Hi $name,\n\nReset your password:\n$link\n\nThis link expires in 15 minutes.",
                )
            }

            "user.password-changed" -> notify(
                recipient, name,
                "Your password was changed",
                "Your password was just changed. If this was not you, reset your password immediately " +
                    "and review your active sessions.",
            )

            "user.email-changed" -> {
                // The *old* address is told as well, so losing control of an inbox is visible.
                event.fields["previous_email"]?.let { previous ->
                    notify(
                        previous, name,
                        "Your email address was changed",
                        "The email address on your account was changed to a new address. " +
                            "If this was not you, contact support immediately.",
                    )
                }
                notify(recipient, name, "Your email address was changed", "This address is now your primary address.")
            }

            "auth.login-succeeded" -> {
                // Only new devices are worth an email; one per sign-in trains people to ignore them.
                if (event.fields["new_device"] == "true") {
                    notify(
                        recipient, name,
                        "New sign-in to your account",
                        "Your account was accessed from a device we have not seen before. " +
                            "If this was not you, change your password and sign out other devices.",
                    )
                }
            }

            "mfa.enrolled", "mfa.enabled" -> notify(
                recipient, name,
                "Two-factor authentication enabled",
                "Two-factor authentication is now active on your account.",
            )

            "mfa.disabled" -> notify(
                recipient, name,
                "Two-factor authentication disabled",
                "Two-factor authentication was turned off on your account. " +
                    "If this was not you, secure your account immediately.",
            )

            "mfa.recovery-code-used" -> notify(
                recipient, name,
                "A recovery code was used",
                "One of your recovery codes was used to sign in. " +
                    "${event.fields["remaining"] ?: "Some"} codes remain. Regenerate them if this was not you.",
            )

            "identity.provider-linked" -> notify(
                recipient, name,
                "A sign-in provider was linked",
                "${event.fields["provider"] ?: "A provider"} was linked to your account.",
            )

            "identity.provider-unlinked" -> notify(
                recipient, name,
                "A sign-in provider was removed",
                "${event.fields["provider"] ?: "A provider"} was removed from your account.",
            )

            "token.refresh-reuse-detected" -> notify(
                recipient, name,
                "Security alert: unusual token activity",
                "We detected a sign-in token being reused, which can mean it was stolen. " +
                    "All sessions for the affected application have been revoked and you will need to sign in " +
                    "again. If you did not expect this, change your password.",
            )

            else -> log.debug("no mail template for {}", event.eventType)
        }
    }

    private suspend fun notify(to: String, name: String, subject: String, body: String) {
        mail.send(
            to = to,
            subject = subject,
            htmlBody = template(name, subject, body, null),
            textBody = "Hi $name,\n\n$body",
        )
    }

    /**
     * Minimal inline-styled HTML.
     *
     * No external images or stylesheets: mail clients block them, and a remote image is a
     * read receipt the recipient did not agree to.
     */
    private fun template(
        name: String,
        heading: String,
        body: String,
        action: Pair<String, String>?,
    ): String = """
        <!doctype html>
        <html><body style="margin:0;padding:24px;background:#F8FAFC;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#0F172A">
          <div style="max-width:520px;margin:0 auto;background:#FFFFFF;border-radius:12px;padding:32px;border:1px solid #E2E8F0">
            <div style="font-size:20px;font-weight:700;color:#5865F2;margin-bottom:24px">HeliumID</div>
            <h1 style="font-size:18px;margin:0 0 12px">${escape(heading)}</h1>
            <p style="margin:0 0 8px;color:#334155">Hi ${escape(name)},</p>
            <p style="margin:0 0 24px;color:#334155;line-height:1.6">${escape(body)}</p>
            ${
        action?.let { (href, label) ->
            """<a href="${escape(href)}" style="display:inline-block;background:#5865F2;color:#fff;
               text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">${escape(label)}</a>
               <p style="margin:24px 0 0;color:#64748B;font-size:12px;word-break:break-all">
               Or paste this link into your browser:<br>${escape(href)}</p>"""
        }.orEmpty()
    }
            <p style="margin:32px 0 0;color:#94A3B8;font-size:12px">
              You are receiving this because someone used this address on HeliumID.
            </p>
          </div>
        </body></html>
    """.trimIndent()

    /** Values come from the database, but escaping is cheap and injection here is real. */
    private fun escape(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
}
