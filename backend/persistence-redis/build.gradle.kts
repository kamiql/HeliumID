dependencies {
    api(project(":flow-engine"))
    api(rootProject.libs.lettuce.core)
    implementation(rootProject.libs.slf4j.api)
    // `await()` on Lettuce's CompletionStage-based async API.
    implementation(rootProject.libs.kotlinx.coroutines.jdk8)
}
