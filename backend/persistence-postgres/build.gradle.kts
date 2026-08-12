plugins {
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(project(":auth-domain"))
    api(project(":flow-engine"))
    api(rootProject.libs.exposed.core)
    api(rootProject.libs.exposed.jdbc)
    implementation(rootProject.libs.exposed.javaTime)
    implementation(rootProject.libs.exposed.json)
    implementation(rootProject.libs.kotlinx.serialization.json)
    implementation(rootProject.libs.hikari)
    implementation(rootProject.libs.flyway.core)
    runtimeOnly(rootProject.libs.flyway.postgresql)
    implementation(rootProject.libs.postgresql)
    implementation(rootProject.libs.logback.classic)
}

// Container-backed suites live in this module because they exercise the real schema.
dependencies {
    testImplementation(project(":test-support"))
}
