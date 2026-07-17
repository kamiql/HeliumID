package dev.kamiql

import dev.kamiql.modules.*
import io.ktor.server.application.*
import org.koin.ktor.plugin.Koin

fun Application.koin() {
    install(Koin) {
        modules(listOf(
            DotenvModule,
            MongoDBModule,
            JsonModule,
            MailModule,
            HttpClientModule
        ))
    }
}