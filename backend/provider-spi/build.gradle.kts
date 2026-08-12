// Service provider interfaces for external identity providers, credential sources and MFA
// methods. Adapters live in their own modules; nothing provider specific belongs here.
dependencies {
    api(project(":auth-domain"))
}
