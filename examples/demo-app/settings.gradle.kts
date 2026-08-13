pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        // Where `./gradlew :helium-client:publishToMavenLocal` puts the SDK.
        mavenLocal()
        // Everything else: Ktor, Nimbus, the Kotlin stdlib.
        mavenCentral()
    }
}

/*
 * A standalone build, deliberately not part of `backend/settings.gradle.kts`.
 *
 * The point of this example is that a subsidiary application can consume HeliumID through the
 * published SDK alone. Including it in the backend build would let it resolve `helium-client` as
 * a project dependency, which would compile happily and prove nothing — the artifact, its POM and
 * its variant metadata would never be exercised.
 *
 * Open this directory as its own IntelliJ project, or import it alongside the backend as a second
 * Gradle build.
 */
rootProject.name = "helium-demo-app"
