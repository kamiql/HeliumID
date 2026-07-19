package dev.kamiql

import io.github.cdimascio.dotenv.Dotenv
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import org.koin.ktor.ext.inject

fun Application.cors() {
    val dotenv: Dotenv by inject()

    install(CORS) {
        allowHost("localhost:5173")
        allowHost("127.0.0.1:5173")

        allowHost(
            dotenv["HOST_URL"].substringAfter("://"),
            listOf("http", "https")
        )

        allowNonSimpleContentTypes = true
        allowCredentials = true

        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)

        HttpMethod.DefaultMethods.forEach(::allowMethod)
    }
}