plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(ktorLibs.plugins.ktor)
    alias(libs.plugins.kotlin.serialization)
    application
}

group = "dev.kamiql"
version = "1.0.0-SNAPSHOT"

application {
    mainClass = "io.ktor.server.netty.EngineMain"
}

kotlin {
    jvmToolchain(25)
}

dependencies {
    implementation(ktorLibs.serialization.kotlinx.json)
    implementation(ktorLibs.server.auth)
    implementation(ktorLibs.server.config.yaml)
    implementation(ktorLibs.server.contentNegotiation)
    implementation(ktorLibs.server.core)
    implementation(ktorLibs.server.cors)
    implementation(ktorLibs.server.netty)
    implementation(ktorLibs.server.sessions)

    implementation(ktorLibs.client.cio)
    implementation(ktorLibs.client.contentNegotiation)

    implementation(libs.flaxoos.ktor.server.rateLimiting)
    implementation(libs.koin.ktor)
    implementation(libs.koin.loggerSlf4j)
    implementation(libs.logback.classic)
    implementation(libs.mongodb.bson)
    implementation(libs.mongodb.driverCore)
    implementation(libs.mongodb.driverSync)

    implementation("org.eclipse.angus:angus-mail:2.0.4")
    implementation("io.github.cdimascio:dotenv-kotlin:6.4.1")
    implementation("at.favre.lib:bcrypt:0.10.2")
}
