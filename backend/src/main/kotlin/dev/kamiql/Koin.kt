package dev.kamiql

import dev.kamiql.modules.*
import dev.kamiql.storage.DefaultDataSeeder
import io.ktor.server.application.*
import kotlinx.coroutines.launch
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

    launch {
        DefaultDataSeeder.seed()
    }
}