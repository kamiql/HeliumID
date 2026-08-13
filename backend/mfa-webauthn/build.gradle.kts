// WebAuthn/passkey second factor. An adapter: the ceremony validation lives here so that
// webauthn4j — and the CBOR/COSE parsing it brings — never reaches the domain modules.
dependencies {
    api(project(":provider-spi"))
    // For the SecurityTransactionStore port that holds single-use challenges. `api` rather than
    // `implementation` because the store appears in the public constructor, so whichever module
    // wires this one has to be able to name the type.
    api(project(":flow-engine"))
    implementation(rootProject.libs.webauthn4j.core)
    implementation(rootProject.libs.slf4j.api)

    // Authenticator emulator. The only way to exercise this adapter honestly: a passkey test
    // without a real signature over a real challenge asserts nothing about the ceremony. Version
    // is pinned to the core artifact deliberately — the emulator and the verifier have to agree
    // on the wire format. Not in the version catalog because no other module has any use for it.
    testImplementation("com.webauthn4j:webauthn4j-test:0.31.9.RELEASE")
}
