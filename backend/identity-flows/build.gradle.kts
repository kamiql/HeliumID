// Application layer: named, typed security flows composed from domain ports.
// No Ktor, no SQL — flows are executable and testable without a server.
dependencies {
    api(project(":auth-domain"))
    api(project(":flow-engine"))
    api(project(":provider-spi"))
    implementation(rootProject.libs.slf4j.api)
}
