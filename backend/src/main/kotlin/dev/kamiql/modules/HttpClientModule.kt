package dev.kamiql.modules

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import org.koin.dsl.module

val HttpClientModule = module {
    single {
        HttpClient(CIO) {
            install(ContentNegotiation) {
                json(get())
            }
        }
    }
}