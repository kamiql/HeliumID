import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}

/**
 * Shared configuration for every HeliumID module.
 *
 * Module boundaries from `CLAUDE.md` are enforced by dependency declarations, not by
 * convention: `auth-domain`, `flow-engine` and `provider-spi` never declare a Ktor, JDBC,
 * Redis or provider-SDK dependency, so importing one is a compile error rather than a
 * review comment.
 */
subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "java-library")

    group = "dev.kamiql.helium"
    version = providers.gradleProperty("heliumVersion").getOrElse("2.0.0-SNAPSHOT")

    extensions.configure<KotlinJvmProjectExtension> {
        jvmToolchain(25)
    }

    dependencies {
        "implementation"(platform(rootProject.libs.junit.bom))
        "implementation"(rootProject.libs.kotlinx.coroutines.core)

        "testImplementation"(kotlin("test"))
        "testImplementation"(rootProject.libs.junit.jupiter)
        "testImplementation"(rootProject.libs.kotlinx.coroutines.test)
        "testImplementation"(rootProject.libs.mockk)
        "testRuntimeOnly"(rootProject.libs.junit.platform.launcher)
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform {
            // Container-backed suites are opt-in so `./gradlew build` stays fast and offline.
            //
            // The guard matters: `configureEach` also sees the `integrationTest` task below, and
            // an exclusion applied there would silently win over its own `includeTags` — leaving
            // a suite that reports success while running nothing.
            if (name != "integrationTest") {
                excludeTags("integration")
            }
        }
        testLogging {
            events("failed")
            showStackTraces = true
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
    }

    tasks.register<Test>("integrationTest") {
        description = "Runs the Testcontainers-backed integration and protocol suites."
        group = "verification"
        // `project.` is load-bearing: a Test task is itself ExtensionAware, so an unqualified
        // `the<SourceSetContainer>()` would look it up on the task and find nothing.
        testClassesDirs = project.the<SourceSetContainer>()["test"].output.classesDirs
        classpath = project.the<SourceSetContainer>()["test"].runtimeClasspath
        useJUnitPlatform {
            includeTags("integration")
        }

        // Testcontainers probes a fixed list of endpoints and does not read the active Docker
        // CLI context. On Windows with Docker Desktop the daemon listens on
        // `npipe:////./pipe/dockerDesktopLinuxEngine`, which is not on that list, so discovery
        // fails even though `docker info` works. Forward the endpoint explicitly — as both an
        // environment variable and a system property, because the two strategies read different
        // sources — and let it be supplied with `-PdockerHost=...` when the shell cannot.
        val dockerHost = providers.environmentVariable("DOCKER_HOST")
            .orElse(providers.gradleProperty("dockerHost"))
        if (dockerHost.isPresent) {
            environment("DOCKER_HOST", dockerHost.get())
            systemProperty("docker.host", dockerHost.get())
        }

        // Docker Engine 29 rejects the older Engine API versions docker-java negotiates by
        // default, answering `/info` with a 400 that Testcontainers reports as "no Docker
        // environment". Pinning a supported version is the fix; override with
        // `-PdockerApiVersion=` if your daemon needs a different one.
        val dockerApiVersion = providers.environmentVariable("DOCKER_API_VERSION")
            .orElse(providers.gradleProperty("dockerApiVersion"))
        if (dockerApiVersion.isPresent) {
            environment("DOCKER_API_VERSION", dockerApiVersion.get())
            systemProperty("api.version", dockerApiVersion.get())
        }

        shouldRunAfter(tasks.named("test"))
    }
}

/** Aggregate entry point: `./gradlew integrationTest` from the root runs every module's suite. */
tasks.register("integrationTest") {
    description = "Runs every module's integration suite."
    group = "verification"
    dependsOn(subprojects.map { "${it.path}:integrationTest" })
}
