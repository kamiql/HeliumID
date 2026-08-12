plugins {
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    implementation(rootProject.libs.slf4j.api)
    api(project(":provider-spi"))
    implementation(project(":security-crypto"))
    implementation(rootProject.libs.nimbus.jose.jwt)
    implementation(rootProject.libs.kotlinx.serialization.json)
    implementation(ktorLibs.client.core)
    implementation(ktorLibs.client.cio)
    implementation(ktorLibs.client.contentNegotiation)
    implementation(ktorLibs.serialization.kotlinx.json)
}
