package dev.kamiql.modules

import io.github.cdimascio.dotenv.dotenv
import org.koin.dsl.module

val DotenvModule = module {
    single {
        dotenv {
            ignoreIfMissing = true
        }
    }
}