package dev.kamiql.modules

import dev.kamiql.serializer.UUIDSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import org.koin.dsl.module
import java.util.*

val JsonModule = module {
    single {
        Json {
            ignoreUnknownKeys = true

            serializersModule = SerializersModule {
                contextual(UUID::class, UUIDSerializer)
            }
        }
    }
}