plugins {
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    implementation(rootProject.libs.slf4j.api)
    api(project(":auth-domain"))
    api(project(":flow-engine"))
    implementation(project(":security-crypto"))
    implementation(rootProject.libs.nimbus.jose.jwt)
    implementation(rootProject.libs.kotlinx.serialization.json)
}
