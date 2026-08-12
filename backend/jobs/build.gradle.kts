plugins {
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    implementation(rootProject.libs.slf4j.api)
    api(project(":flow-engine"))
    implementation(project(":persistence-postgres"))
    implementation(project(":protocol-oauth2-oidc"))
    implementation(rootProject.libs.kotlinx.serialization.json)
    implementation(rootProject.libs.angus.mail)
    implementation(rootProject.libs.logback.classic)
}
