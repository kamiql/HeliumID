plugins {
    kotlin("jvm") version "2.4.0"
    // The JSON DTOs of the bearer API, and the session cookie's payload.
    kotlin("plugin.serialization") version "2.4.0"
    application
}

group = "dev.kamiql.helium.demo"
version = "1.0.0"

kotlin {
    /*
     * Must be 25 or higher, and this is not a stylistic choice.
     *
     * The published `helium-client` module metadata records `org.gradle.jvm.version = 25`. A
     * consumer on a lower toolchain fails during *variant resolution* with "requires at least a
     * Java 25 JVM", which reads like a missing artifact rather than a toolchain mismatch.
     */
    jvmToolchain(25)
}

application {
    mainClass.set("dev.kamiql.helium.demo.ApplicationKt")
}

/*
 * Ktor coordinates are written out in full. The backend build pulls them from the remote
 * `ktor-version-catalog`, but that is a convenience of *its* build script — the published SDK
 * carries no catalog, so a consumer names the versions itself. 3.5.0 matches what the SDK was
 * compiled against.
 */
val ktor = "3.5.0"

dependencies {
    // The whole point of the example. Publish it first:
    //   cd ../../backend && ./gradlew :helium-client:publishToMavenLocal
    implementation("dev.kamiql.helium:helium-client:2.0.0-SNAPSHOT")

    // `helium-client` exports ktor-client-core, ktor-server-core and ktor-server-auth as `api`
    // dependencies, so those arrive transitively. Everything below is this application's own.
    implementation("io.ktor:ktor-server-netty:$ktor")
    implementation("io.ktor:ktor-server-html-builder:$ktor")
    implementation("io.ktor:ktor-server-content-negotiation:$ktor")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor")
    implementation("io.ktor:ktor-server-sessions:$ktor")
    implementation("io.ktor:ktor-server-status-pages:$ktor")
    implementation("io.ktor:ktor-server-call-logging:$ktor")
    implementation("io.ktor:ktor-client-cio:$ktor")
    // Cookie support, for the one place that speaks to HeliumID as a browser would: the setup
    // CLI, which has to hold a session to register the client.
    implementation("io.ktor:ktor-client-content-negotiation:$ktor")

    // ID-token verification. The SDK depends on Nimbus internally but does not expose it (it is
    // `implementation`, not `api`), and verifying an ID token is the consumer's job, not the
    // SDK's — so it is named here explicitly.
    implementation("com.nimbusds:nimbus-jose-jwt:10.5")

    implementation("ch.qos.logback:logback-classic:1.5.18")

    testImplementation(kotlin("test"))
    testImplementation("io.ktor:ktor-server-test-host:$ktor")
    testImplementation("io.ktor:ktor-client-mock:$ktor")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

/** `./gradlew setup` — registers the scopes and the OAuth client this demo needs. */
tasks.register<JavaExec>("setup") {
    group = "application"
    description = "Registers the demo's scopes and OAuth client in HeliumID."
    mainClass.set("dev.kamiql.helium.demo.SetupKt")
    classpath = sourceSets["main"].runtimeClasspath
}
