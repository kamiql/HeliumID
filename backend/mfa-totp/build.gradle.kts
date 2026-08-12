dependencies {
    api(project(":provider-spi"))
    implementation(project(":security-crypto"))
    implementation(rootProject.libs.totp)
    implementation(rootProject.libs.slf4j.api)
}
