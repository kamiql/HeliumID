plugins {
    alias(libs.plugins.kotlin.serialization)
    application
}

application {
    mainClass = "dev.kamiql.helium.app.MainKt"
    applicationName = "helium-id"
}

dependencies {
    implementation(project(":api-http"))
    implementation(project(":persistence-postgres"))
    implementation(project(":persistence-redis"))
    implementation(project(":provider-oidc"))
    implementation(project(":mfa-totp"))
    implementation(project(":mfa-webauthn"))
    implementation(project(":security-crypto"))
    // For ScrubbedAuditPort, which wraps the audit repository in the flow runner.
    implementation(project(":audit-risk"))
    implementation(project(":jobs"))

    implementation(ktorLibs.server.core)
    implementation(ktorLibs.client.core)
    implementation(ktorLibs.client.cio)
    implementation(ktorLibs.client.contentNegotiation)
    implementation(ktorLibs.serialization.kotlinx.json)
    implementation(ktorLibs.server.netty)
    implementation(ktorLibs.server.metrics.micrometer)
    implementation(rootProject.libs.micrometer.prometheus)
    implementation(rootProject.libs.logback.classic)
    implementation(rootProject.libs.logstash.encoder)
    implementation(rootProject.libs.kotlinx.serialization.json)

    testImplementation(project(":test-support"))
    testImplementation(ktorLibs.server.testHost)
    testImplementation(ktorLibs.client.contentNegotiation)
}
