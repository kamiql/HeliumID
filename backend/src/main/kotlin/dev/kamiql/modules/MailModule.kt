package dev.kamiql.modules

import dev.kamiql.services.MailService
import dev.kamiql.services.MailTemplateService
import org.koin.dsl.module

val MailModule = module {
    single {
        MailService(get(), get())
    }

    single {
        MailTemplateService(get())
    }
}