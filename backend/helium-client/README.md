# helium-client

The SDK for talking to HeliumID. Two halves, usable independently:

| | What it is | Use it when |
|---|---|---|
| **`HeliumId`** | A Ktor server plugin that verifies HeliumID access tokens and protects routes | Your service *receives* requests carrying a HeliumID token |
| **`HeliumIdClient`** | A typed suspending client for every HeliumID endpoint | Your service *calls* HeliumID — token exchange, user management, admin |

Everything is `dev.kamiql.helium.client`. The module is compiled in explicit API mode and is
the only published artifact, so its surface is a contract: it does not depend on `auth-domain`,
`persistence-postgres` or anything else internal.

---

## 1. Add the dependency

```kotlin
// build.gradle.kts
dependencies {
    implementation("dev.kamiql.helium:helium-client:2.0.0")
}
```

It brings `ktor-client-core`, `ktor-server-core` and `ktor-server-auth` transitively, plus
Nimbus for all JOSE work. A CIO client engine ships as a runtime dependency so
`HeliumIdClient.create(...)` works out of the box; pass your own `HttpClient` and it is unused.

---

## 2. Protect a service

```kotlin
fun Application.module() {
    install(HeliumId) {
        issuer = "https://id.example"        // must match the `iss` claim exactly
        audience = "orders-api"              // this service's own audience — do set it
        jwks { cacheFor = 10.minutes }       // offline ES256 verification, the default
    }

    routing {
        authenticate("heliumid") {

            get("/orders") {
                val principal = call.requireHeliumPrincipal()
                call.respond(orders.forUser(principal.userId!!))
            }

            // All of these scopes.
            requireScope("orders:read") {
                get("/orders/{id}") { /* ... */ }
            }

            // Any of these roles. See the caveat below.
            requireRole("ADMINISTRATOR") {
                delete("/orders/{id}") { /* ... */ }
            }
        }
    }
}
```

`call.heliumPrincipal()` returns a nullable `HeliumPrincipal`; `call.requireHeliumPrincipal()`
throws if the route is not behind the provider, which is the honest thing to do inside a
mandatory `authenticate` block.

### What the plugin validates

`iss` (exact), `aud` (exact, when configured), `exp`, `nbf`, and an **ES256** signature against
a key resolved by `kid` from the issuer's JWKS. The algorithm set is pinned to ES256 alone, so
`alg: none` and the "HMAC the token with the EC public key" confusion attack both fail at key
selection. Set `audience` — without it, a token minted for any sibling service of the same
issuer is accepted here.

### What it does not

Authorization. A valid token says *who* is calling, not what they may do.

### Failure responses

| Situation | Status | Body `code` | `WWW-Authenticate` |
|---|---|---|---|
| No `Authorization: Bearer` | 401 | `auth_required` | `Bearer realm="identity", error="invalid_request"` |
| Bad signature, wrong `iss`/`aud`, expired, unknown `kid`, wrong `alg` | 401 | `invalid_token` | `Bearer realm="identity", error="invalid_token"` |
| Missing scope or role | 403 | `forbidden` | — |
| JWKS or introspection unreachable | 503 | `temporarily_unavailable` | — |

Bodies are RFC 9457 `application/problem+json` using the same `code` values HeliumID itself
emits, so a client needs one error branch rather than two. Every rejection collapses to the same
`invalid_token` detail on purpose — telling a caller *why* their forged token failed is free
debugging for an attacker.

### A note on `requireRole`

HeliumID access tokens carry the concept §4.2 claim set and **no roles**: a bearer token travels
through logs, proxies and crash dumps, and every extra claim is data leaked to all of them.
`requireRole` therefore denies everything unless your deployment configures the issuer to emit a
roles claim and you point `rolesClaim` at it. For service-to-service authorization you almost
certainly want `requireScope`.

---

## 3. Call HeliumID

```kotlin
val helium = HeliumIdClient.create("https://id.example") {
    bearerToken { tokenStore.currentAccessToken() }   // called per request; may refresh
}

// Authorization Code + PKCE — the only interactive flow HeliumID accepts.
val pkce = Pkce.generate()
val state = Pkce.generateState()

val url = helium.authorizationUrl(
    clientId = "orders-web",
    redirectUri = "https://orders.example/callback",
    scope = setOf("openid", "profile", "orders:read"),
    state = state,
    codeChallenge = pkce.challenge,
)
// ...redirect the user agent, then on the callback (after checking `state`):

val tokens = helium.exchangeAuthorizationCode(
    code = code,
    redirectUri = "https://orders.example/callback",
    clientId = "orders-web",
    codeVerifier = pkce.verifier,
)
```

Errors are a sealed hierarchy, so you branch on types rather than strings:

```kotlin
try {
    helium.login(identifier, password)
} catch (e: HeliumApiException) {
    when (val error = e.error) {
        is HeliumError.MfaRequired      -> openChallenge(error.transactionId, error.methods)
        is HeliumError.InvalidCredentials -> showGenericFailure()      // never "no such user"
        is HeliumError.RateLimited      -> backOff(error.retryAfter)
        is HeliumError.EmailUnverified  -> promptResendVerification()
        else                            -> throw e
    }
}
```

`HeliumApiException` means the server said no; `HeliumTransportException` means there was no
usable answer. The server's stable `code` is preserved on every variant, and anything this SDK
does not model arrives as `HeliumError.Unexpected(status, code)` rather than being swallowed.

### Refresh tokens rotate

The response to a refresh contains a **new** refresh token that replaces the one you sent.
Persist it before using the access token, and never retry a failed refresh with the old value:
presenting a spent token is treated as theft and revokes the whole family, signing every device
out. An `InvalidGrant` on refresh means re-authenticate, not retry.

### Cookie sessions

The `/v1/auth/*` and `/v1/me/*` endpoints also accept a browser session cookie. For that you
need a cookie-aware `HttpClient` and the double-submit CSRF token:

```kotlin
val helium = HeliumIdClient.create("https://id.example") {
    httpClient = HttpClient(CIO) { install(HttpCookies) }
    csrfToken { csrfStore.current() }        // from HeliumIdClient.session()
}
```

Re-read the CSRF token after every authentication: the server issues a fresh one on sign-in, so
a value captured beforehand stops working.

### One-shot secrets

`enrollTotp()`, `confirmTotp()`, `regenerateRecoveryCodes()`, `registerClient()` and
`rotateClientSecret()` are the only calls that ever return a secret, and none of them can be
replayed. Show it or store it immediately; the server keeps only a hash.

---

## 4. Offline verification vs introspection

Both modes are supported. They are a genuine trade-off, not a quality ladder.

### Offline JWKS (default)

The signature is checked locally against a cached copy of the issuer's public keys.

- **No network hop** on the request path, and no per-request load on the identity server.
- **No availability coupling** — if HeliumID is down, your already-issued tokens keep working.
- **Revocation is late.** A token revoked before it expires keeps verifying until it expires.
  HeliumID keeps access tokens to five minutes precisely so that window is small.

Tuning that matters:

```kotlin
jwks {
    cacheFor = 10.minutes      // key rotation keeps an overlap window; 10m sits inside it
    refreshTimeout = 15.seconds // one thread refreshes, the rest wait — no thundering herd
    rateLimitFor = 30.seconds   // an unknown `kid` triggers at most one refresh per interval
}
```

`rateLimitFor` is a defence, not an optimisation: without it a stream of tokens carrying forged
key ids turns every request into a JWKS fetch — an amplified DoS pointed at HeliumID.

### Introspection (opt-in)

Every token is checked against `/oauth2/introspect`, which consults the revocation deny list.

```kotlin
introspection {
    enabled = true
    clientId = "orders-api"
    clientSecret = System.getenv("HELIUM_CLIENT_SECRET")
    cacheFor = 10.seconds       // this is your revocation latency
}
```

- **Revocation is immediate**, bounded by `cacheFor`.
- **You pay a round trip** on the request path and inherit HeliumID's availability. This mode
  fails **closed**: an unreachable identity server means `503`, never "assume valid".
- The signature is still verified offline **first**, so forged and malformed tokens are rejected
  without spending a call, and introspection only ever sees structurally valid tokens.
- Cache keys are a SHA-256 of the token, never the token; entries never outlive the token's own
  `exp`.

### Choosing

| | Offline JWKS | Introspection |
|---|---|---|
| Latency added | none | one round trip, cached |
| Availability | independent | coupled, fails closed |
| Revocation window | remaining token lifetime (≤ 5 min) | `cacheFor` (default 10 s) |
| Load on HeliumID | one JWKS fetch per `cacheFor` | one call per token per `cacheFor` |

**Default to offline.** Reach for introspection on the narrow surfaces where a five-minute
revocation window is genuinely unacceptable — money movement, admin actions, anything that ends
a session elsewhere — rather than turning it on service-wide.

---

## 5. Things this SDK will not do

- No password grant, no implicit flow, no PKCE `plain`. They are not omissions.
- No arbitrary issuer or redirect URI. `issuer` is matched exactly; the redirect URI is
  validated by the server against the client registration.
- No token or secret ever reaches a log line, a `toString()`, or an exception message —
  including in `HeliumPrincipal` and `PkcePair`, both of which redact themselves.
- No account linking by matching email addresses. Linking requires an authenticated session.
