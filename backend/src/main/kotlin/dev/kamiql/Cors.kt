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
        allowHost(dotenv["HOST_URL"].substringAfter("://"), listOf("https"))
        allowHeader(HttpHeaders.ContentType)
        allowCredentials = true
    }
}