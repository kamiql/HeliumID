// Adapter module: concrete implementations of the cryptographic ports declared by the domain.
// Nothing here invents cryptography; every primitive comes from an audited library or the JCA.
dependencies {
    api(project(":auth-domain"))
    implementation(rootProject.libs.bouncycastle.provider)
}
