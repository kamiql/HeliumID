dependencies {
    implementation(rootProject.libs.slf4j.api)
    api(project(":auth-domain"))
    api(project(":flow-engine"))
}
