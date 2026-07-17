package dev.kamiql.services

import dev.kamiql.domain.user.User
import io.github.cdimascio.dotenv.Dotenv
import java.io.InputStream
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

class MailTemplateService(
    private val dotenv: Dotenv
) {
    fun render(
        template: String,
        user: User? = null,
        variables: Map<String, Any?> = emptyMap()
    ): String {
        return renderInternal(template, user, variables, true)
    }

    fun renderRaw(
        template: String,
        user: User? = null,
        variables: Map<String, Any?> = emptyMap()
    ): String {
        return renderInternal(template, user, variables, false)
    }

    private fun renderInternal(
        template: String,
        user: User?,
        variables: Map<String, Any?>,
        escape: Boolean
    ): String {
        val context = defaultVariables(user) + variables
        val content = loadTemplate(template)

        return Regex("""\{\{(\w+)}}""")
            .replace(content) { match ->
                val value = context[match.groupValues[1]]?.toString() ?: ""

                if (escape) {
                    htmlEscape(value)
                } else {
                    value
                }
            }
    }

    private fun defaultVariables(user: User?): Map<String, Any?> {
        val now = ZonedDateTime.now(ZoneId.systemDefault())

        return buildMap {
            put("date", now.format(DateTimeFormatter.ofPattern("dd.MM.yyyy")))
            put("time", now.format(DateTimeFormatter.ofPattern("HH:mm")))
            put("datetime", now.format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")))
            put("year", now.year)
            put("hostUrl", dotenv["HOST_URL"])

            user?.let {
                put("id", it.id)
                put("username", it.username)
                put("username_lower", it.username_lower)
                put("firstName", it.firstName)
                put("lastName", it.lastName)
                put("email", it.email)
                put("emailVerified", it.emailVerified)
                put("createdAt", it.createdAt)
            }
        }
    }

    private fun loadTemplate(template: String): String {
        val path = "emails/$template.html"

        val stream: InputStream = javaClass.classLoader
            .getResourceAsStream(path)
            ?: error("Mail template not found: $path")

        return stream.bufferedReader().use { it.readText() }
    }

    private fun htmlEscape(value: String): String {
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
    }
}