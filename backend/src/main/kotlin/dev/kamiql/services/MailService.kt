package dev.kamiql.services

import dev.kamiql.domain.user.User
import io.github.cdimascio.dotenv.Dotenv
import jakarta.mail.*
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import java.util.*

class MailService(
    private val dotenv: Dotenv,
    private val mailTemplateService: MailTemplateService
) {
    fun send(
        user: User,
        subject: String,
        template: String,
        variables: Map<String, Any?> = emptyMap()
    ) {
        send(
            listOf(user.email.toString()),
            subject,
            mailTemplateService.render(template, user, variables)
        )
    }

    fun send(
        to: List<String>,
        subject: String,
        html: String
    ) {
        val props = Properties().apply {
            put("mail.smtp.host", dotenv["SMTP_HOST"])
            put("mail.smtp.port", "587")
            put("mail.smtp.auth", "true")
            put("mail.smtp.starttls.enable", "true")
        }

        val session = Session.getInstance(props, object : Authenticator() {
            override fun getPasswordAuthentication() =
                PasswordAuthentication(
                    dotenv["SMTP_USER"],
                    dotenv["SMTP_PASSWORD"]
                )
        })

        val message = MimeMessage(session).apply {
            setFrom(InternetAddress(dotenv["SMTP_USER"]))
            setRecipients(
                Message.RecipientType.TO,
                InternetAddress.parse(to.joinToString(","))
            )
            setSubject(subject, "UTF-8")
            setContent(html, "text/html; charset=utf-8")
        }

        Transport.send(message)
    }
}