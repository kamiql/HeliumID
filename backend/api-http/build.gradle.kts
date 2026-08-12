plugins {
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    implementation(rootProject.libs.slf4j.api)
    api(project(":auth-domain"))
    api(project(":flow-engine"))
    api(project(":protocol-oauth2-oidc"))
    api(project(":audit-risk"))
    api(project(":provider-spi"))
    api(project(":identity-flows"))
    implementation(project(":mfa-totp"))
    implementation(project(":security-crypto"))

    implementation(ktorLibs.server.core)
    implementation(ktorLibs.server.auth)
    implementation(ktorLibs.server.contentNegotiation)
    implementation(ktorLibs.server.statusPages)
    implementation(ktorLibs.server.callId)
    implementation(ktorLibs.server.callLogging)
    implementation(ktorLibs.server.cors)
    implementation(ktorLibs.server.defaultHeaders)
    implementation(ktorLibs.server.forwardedHeader)
    implementation(ktorLibs.server.requestValidation)
    implementation(ktorLibs.serialization.kotlinx.json)
    implementation(rootProject.libs.kotlinx.serialization.json)

    testImplementation(ktorLibs.server.testHost)
}
