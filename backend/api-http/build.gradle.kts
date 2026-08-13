plugins {
    alias(libs.plugins.kotlin.serialization)
    // The route enumerator is shared: `api-http` uses it to hold `docs/api-routes.md` to the
    // routing tree, and `app` uses the same walk to drive the end-to-end coverage census.
    `java-test-fixtures`
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

    testFixturesImplementation(ktorLibs.server.core)

    testImplementation(ktorLibs.server.testHost)
    testImplementation(testFixtures(project(":api-http")))
}

// `-D` on the Gradle command line reaches the daemon, not the forked test JVM. RouteInventoryTest
// regenerates `docs/api-routes.md` when this is set, so it has to be forwarded explicitly.
tasks.withType<Test>().configureEach {
    systemProperty(
        "helium.routes.write",
        providers.systemProperty("helium.routes.write").getOrElse("false"),
    )
}
