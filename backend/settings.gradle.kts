pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
    versionCatalogs {
        create("ktorLibs").from("io.ktor:ktor-version-catalog:3.5.0")
    }
}

rootProject.name = "helium-id"

// --- domain core: no framework dependencies allowed -------------------------
include("auth-domain")
include("flow-engine")
include("provider-spi")

// --- adapters ---------------------------------------------------------------
include("security-crypto")
include("provider-oidc")
include("mfa-totp")
include("persistence-postgres")
include("persistence-redis")

// --- protocol & application -------------------------------------------------
include("identity-flows")
include("protocol-oauth2-oidc")
include("audit-risk")
include("api-http")
include("jobs")
include("app")

// --- consumer facing --------------------------------------------------------
include("helium-client")

// --- testing ----------------------------------------------------------------
include("test-support")
