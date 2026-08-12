// Flow orchestration and ports. Framework free: slf4j-api is a logging facade, not a runtime.
dependencies {
    api(project(":auth-domain"))
    implementation(rootProject.libs.slf4j.api)
}
