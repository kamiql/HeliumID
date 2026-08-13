import { ErrorCode, HeliumError } from "../api/problem.ts"
import type {
    WebauthnAssertion,
    WebauthnAssertionOptions,
    WebauthnEnrollOptions,
    WebauthnRegistration,
} from "../api/types.ts"

/**
 * The browser half of the WebAuthn ceremonies.
 *
 * This module is the only place that touches `navigator.credentials`. It translates between the
 * wire shape — snake_case fields, binary values as **base64url** strings — and the `ArrayBuffer`
 * types the platform API insists on, and it turns the ceremony's `DOMException`s into the same
 * [HeliumError] the rest of the app already knows how to render.
 *
 * Nothing here is persisted. Challenges and credential material live for the duration of one
 * call and are never written to storage or logged.
 */

// --- base64url ------------------------------------------------------------------

/*
 * base64url (RFC 4648 §5), not base64: `-` and `_` replace `+` and `/`, and the `=` padding is
 * dropped. `atob`/`btoa` only speak standard base64, so both directions have to convert — a
 * missed substitution decodes to plausible-looking bytes and fails only at signature
 * verification, which is the worst possible place to find out.
 */

export function base64UrlToBuffer(value: string): ArrayBuffer {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/")
    const padding = (4 - (base64.length % 4)) % 4
    const binary = atob(base64 + "=".repeat(padding))

    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index)
    }

    return bytes.buffer
}

export function bufferToBase64Url(value: ArrayBuffer): string {
    let binary = ""
    for (const byte of new Uint8Array(value)) {
        binary += String.fromCharCode(byte)
    }

    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// --- availability ---------------------------------------------------------------

/**
 * Why this browser cannot run a ceremony, or `null` when it can.
 *
 * Two separate reasons because they need two different answers: an old browser is the user's
 * problem to solve, an origin served over plain HTTP is ours. `navigator.credentials` is gated
 * on a secure context, so on `http://` the API is simply absent and the ceremony would fail
 * with nothing a user could act on.
 */
export function webauthnUnavailable(): HeliumError | null {
    if (typeof window === "undefined" || typeof window.PublicKeyCredential !== "function") {
        return new HeliumError(null, 0, ErrorCode.WEBAUTHN_UNSUPPORTED)
    }

    // `localhost` counts as secure, so development over HTTP still works.
    if (!window.isSecureContext) {
        return new HeliumError(null, 0, ErrorCode.WEBAUTHN_INSECURE_CONTEXT)
    }

    return null
}

/** Whether a passkey control should be offered at all. */
export function isWebauthnAvailable(): boolean {
    return webauthnUnavailable() === null
}

/**
 * Maps a ceremony rejection onto a stable code.
 *
 * `NotAllowedError` covers both "the user closed the prompt" and "the timeout elapsed": the
 * spec deliberately conflates them so a page cannot tell whether an authenticator was present.
 * Either way it is a decision rather than a fault, and the UI treats it as one.
 */
function toCeremonyError(caught: unknown): HeliumError {
    if (caught instanceof HeliumError) return caught

    if (caught instanceof DOMException) {
        switch (caught.name) {
            case "NotAllowedError":
            case "AbortError":
                return new HeliumError(null, 0, ErrorCode.WEBAUTHN_CANCELLED)
            case "InvalidStateError":
                return new HeliumError(null, 0, ErrorCode.WEBAUTHN_ALREADY_REGISTERED)
            case "NotSupportedError":
                return new HeliumError(null, 0, ErrorCode.WEBAUTHN_UNSUPPORTED)
            default:
                break
        }
    }

    return new HeliumError(null, 0, ErrorCode.WEBAUTHN_FAILED)
}

// --- ceremonies -----------------------------------------------------------------

/**
 * Registration: `navigator.credentials.create()`.
 *
 * Only the parameters the server sent are passed on. Nothing is added here — no attestation
 * preference, no resident-key request — because the ceremony's shape is a server policy
 * decision and a client that quietly asks for more produces credentials the server did not
 * agree to.
 *
 * Must be called from a user gesture: Safari drops the transient activation that WebAuthn
 * requires if too long passes between the click and the call.
 */
export async function createWebauthnCredential(
    options: WebauthnEnrollOptions,
): Promise<WebauthnRegistration> {
    const unavailable = webauthnUnavailable()
    if (unavailable) throw unavailable

    let credential: Credential | null
    try {
        credential = await navigator.credentials.create({
            publicKey: {
                challenge: base64UrlToBuffer(options.challenge),
                rp: { id: options.rp_id, name: options.rp_name },
                user: {
                    id: base64UrlToBuffer(options.user_handle),
                    name: options.user_name,
                    displayName: options.user_display_name,
                },
                pubKeyCredParams: options.algorithms.map((alg) => ({ type: "public-key", alg })),
                excludeCredentials: options.exclude_credential_ids.map((id) => ({
                    type: "public-key",
                    id: base64UrlToBuffer(id),
                })),
                authenticatorSelection: { userVerification: options.user_verification },
                timeout: options.timeout_ms,
            },
        })
    } catch (caught) {
        throw toCeremonyError(caught)
    }

    if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAttestationResponse)
    ) {
        throw new HeliumError(null, 0, ErrorCode.WEBAUTHN_FAILED)
    }

    const response = credential.response

    return {
        credential_id: bufferToBase64Url(credential.rawId),
        client_data_json: bufferToBase64Url(response.clientDataJSON),
        attestation_object: bufferToBase64Url(response.attestationObject),
        // Added in a later revision of the spec, so still worth guarding: the hint lets the
        // server offer the right prompt next time, and an empty list only costs that hint.
        transports: typeof response.getTransports === "function" ? response.getTransports() : [],
    }
}

/**
 * Authentication: `navigator.credentials.get()`.
 *
 * Same gesture requirement as registration. The challenge is single-use — a rejected assertion
 * means fetching a new one rather than replaying this ceremony.
 */
export async function getWebauthnAssertion(
    options: WebauthnAssertionOptions,
): Promise<WebauthnAssertion> {
    const unavailable = webauthnUnavailable()
    if (unavailable) throw unavailable

    let credential: Credential | null
    try {
        credential = await navigator.credentials.get({
            publicKey: {
                challenge: base64UrlToBuffer(options.challenge),
                rpId: options.rp_id,
                allowCredentials: options.allow_credential_ids.map((id) => ({
                    type: "public-key",
                    id: base64UrlToBuffer(id),
                })),
                userVerification: options.user_verification,
                timeout: options.timeout_ms,
            },
        })
    } catch (caught) {
        throw toCeremonyError(caught)
    }

    if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAssertionResponse)
    ) {
        throw new HeliumError(null, 0, ErrorCode.WEBAUTHN_FAILED)
    }

    const response = credential.response

    return {
        credential_id: bufferToBase64Url(credential.rawId),
        client_data_json: bufferToBase64Url(response.clientDataJSON),
        authenticator_data: bufferToBase64Url(response.authenticatorData),
        signature: bufferToBase64Url(response.signature),
        user_handle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    }
}
