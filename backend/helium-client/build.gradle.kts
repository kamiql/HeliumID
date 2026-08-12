plugins {
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
    `java-library`
}

// The SDK is the only module compiled in explicit API mode: every public symbol must declare
// its visibility and return type, because downstream Ktor projects depend on this surface.
extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
    explicitApi()
}

java {
    withSourcesJar()
}

dependencies {
    api(ktorLibs.client.core)
    api(ktorLibs.server.core)
    api(ktorLibs.server.auth)
    implementation(ktorLibs.client.contentNegotiation)
    // Runtime-only default engine, so `HeliumIdClient.create(...)` works without the consumer
    // choosing one. It is deliberately not `api`: pass your own HttpClient and this is unused.
    implementation(ktorLibs.client.cio)
    implementation(ktorLibs.serialization.kotlinx.json)
    implementation(rootProject.libs.kotlinx.serialization.json)
    implementation(rootProject.libs.nimbus.jose.jwt)

    testImplementation(ktorLibs.client.cio)
    testImplementation(ktorLibs.client.mock)
    testImplementation(ktorLibs.server.testHost)
    // A real socket, so the JWKS fetch in the protocol tests goes over HTTP like it does in
    // production. Nimbus's resource retriever will not accept an in-memory test engine.
    testImplementation(ktorLibs.server.cio)
    testImplementation(ktorLibs.server.contentNegotiation)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "helium-client"
            from(components["java"])
            pom {
                name.set("HeliumID Client")
                description.set("Ktor server plugin and typed client for the HeliumID identity provider.")
            }
        }
    }
}
