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
    // The end-to-end suite asks the routing tree what exists, using the same walk that generates
    // `docs/api-routes.md`, so the coverage census and the document cannot disagree about the
    // shape of a route.
    testImplementation(testFixtures(project(":api-http")))
    // Routes and DTOs are an `implementation` dependency of this module, which does not reach the
    // test compile classpath. The suite posts real request bodies, so it needs them directly.
    testImplementation(project(":api-http"))
}

/**
 * Runs the whole end-to-end suite in one JVM, in a fixed class order.
 *
 * Both matter to the coverage census in `RouteCoverageTest`: it reads a counter every other test
 * class writes to, so it has to share their JVM and run after them. The ordering itself is
 * configured in `src/test/resources/junit-platform.properties`.
 */
tasks.named<Test>("integrationTest") {
    forkEvery = 0
    maxParallelForks = 1
}
