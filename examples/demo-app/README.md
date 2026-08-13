# Helium Demo Workspace

A small Ktor application that uses HeliumID as its identity provider, built entirely against the
published `helium-client` SDK. It signs users in with OAuth 2.0 Authorization Code + PKCE and then
shows the three separate authorization questions a real integration has to answer.

This is a **standalone Gradle build**. It is deliberately not part of `backend/settings.gradle.kts`:
it resolves `dev.kamiql.helium:helium-client` from `mavenLocal`, exactly as a subsidiary
application would. Open this directory as its own IntelliJ project.

---

## Running it

**Prerequisites**: a JDK 25 toolchain (the published SDK records `org.gradle.jvm.version = 25`,
and a lower toolchain fails at variant resolution with a confusing message), Docker, and `curl`.

```bash
./run-demo.sh
```

That is the whole thing. It starts the HeliumID dev stack if it is not already up, publishes the
SDK to `mavenLocal` if it is missing, registers the scopes and OAuth client if they do not exist,
and then runs the application in the foreground. Every step is skipped when it is already done, so
re-running it is cheap and safe.

Then open <http://localhost:8081> and sign in. The bootstrap administrator from `.env.dev.example`
is `admin` / `dev-only-change-me`; register a second account through HeliumID to try sharing and
the non-admin view.

| Flag | |
| --- | --- |
| `--reset` | delete and re-register the OAuth client first |
| `--no-stack` | never touch Docker; fail if HeliumID is not already reachable |
| `--republish` | force `publishToMavenLocal` even when the SDK is present |
| `--setup-only` | do everything except starting the application |

### Doing it by hand

```bash
cd ../.. && cp .env.dev.example .env.dev
docker compose --env-file .env.dev -f docker-compose.dev.yml up --build
cd backend && ./gradlew :helium-client:publishToMavenLocal
cd ../examples/demo-app && ./gradlew setup     # prints the client secret, once

export DEMO_CLIENT_SECRET="…"        # bash
$env:DEMO_CLIENT_SECRET="…"          # PowerShell
./gradlew run
```

### How the script keeps the secret

HeliumID shows a client secret exactly once, at registration, and will not read it back. The
script caches it in `.demo-secret` (gitignored, `chmod 600`) and validates it on every run by
presenting a deliberately bogus refresh token at the token endpoint: client authentication is
checked before the grant is, so `invalid_grant` means the secret was accepted and `invalid_client`
means it was not. That is the only read-back HeliumID offers, and it costs no sign-in.

When the cache is stale — a reset database, a secret rotated elsewhere, a deleted file — the
script recovers by rotating the secret rather than failing. An explicitly exported
`DEMO_CLIENT_SECRET` is treated as an instruction instead: if it does not work the script says so
and stops, rather than quietly rotating a credential you chose.

**Sign-ins are rate-limited to 5 per account per 10 minutes**, so the script spends at most one
per run. It works out whether the client already exists by reading the status code of an
unauthenticated `GET /oauth2/authorize` (302 registered · 400 wrong redirect URI · 403 no such
client), which costs nothing, and only then decides between registering and rotating. `--reset`
is the exception and spends two: one to delete, one to register.

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HELIUM_ISSUER` | `http://localhost:90` | Must match the `iss` claim exactly |
| `DEMO_BASE_URL` | `http://localhost:8081` | Redirect URI is `$DEMO_BASE_URL/callback` |
| `DEMO_PORT` | `8081` | |
| `DEMO_CLIENT_ID` | `helium-demo` | |
| `DEMO_CLIENT_SECRET` | — | Required. Minted once by `setup`; `run-demo.sh` caches it in `.demo-secret` |
| `DEMO_AUDIENCE` | `helium-demo-api` | The `aud` of access tokens, and what this app's API validates |
| `HELIUM_ADMIN_USERNAME` / `HELIUM_ADMIN_PASSWORD` | `admin` / `dev-only-change-me` | `setup` only |

---

## Why `setup` needs a password instead of a token

Client registration goes through a flow that declares `ReauthenticatedWithin(5 minutes)`, and that
requirement **rejects any principal that is not a browser session** — a `client_credentials` token
can never satisfy it, however privileged the client. So the only way to automate registration is
to do what a browser does: sign in, then act inside the reauthentication window.

`Setup.kt` therefore uses a cookie-aware HTTP client, bootstraps a CSRF token from
`/v1/auth/session`, logs in, and re-reads the CSRF token because the server rotates it on
authentication. Any integrator scripting client registration will meet the same constraint.

---

## The three authorization axes

The interesting part of the demo. They answer different questions and none substitutes for another.

### 1. Document roles — what *this user* may do *here*

`domain/Workspace.kt`. Owner, editor, viewer, per document, keyed on the HeliumID `sub` claim.

HeliumID knows nothing about these and should not: it has no per-application permissions and no
tenancy, so "editor of document 7" has nowhere to live there. What it supplies is the stable
identity the grants hang from — `sub`, not the username or email, both of which a user can change.

A viewer posting to the edit form is refused server-side; the hidden form is a convenience, not the
check. A document you have no grant on answers `not found`, identically to one that never existed —
distinguishing them would confirm which ids are real.

### 2. HeliumID permissions — what *this user* may do *in the identity system*

The admin area, gated on `admin:user:read`.

**Permissions are in no token at all.** Not the access token, not the ID token, not `/userinfo` —
HeliumID keeps access tokens to the OIDC §4.2 claim set, because every extra claim is data leaked
into every log and proxy the token passes through. They come from `GET /v1/me`, which reads the
flattened permission set from the database on every call. The upside is immediate revocation: take
a role away and the next request is already refused, with no token refresh and no sign-out.

The admin area is mostly read-only, and the reason is worth seeing rather than hiding. Nearly every
write under `/v1/admin` declares `ReauthenticatedWithin`, which a bearer principal can never
satisfy. Exactly two do not: revoking a user's sessions, and scope CRUD. The **Suspend** button is
wired to `PUT /v1/admin/users/{id}/status` on purpose so you can watch it fail with
`reauthentication_required`.

`requireRole(...)` from the SDK is deliberately unused: HeliumID emits no `roles` claim, so it
would reject everyone.

### 3. OAuth scopes — what *this application* may do on the user's behalf

`api/DocumentsApi.kt`, a bearer-authenticated JSON API on the same server:

```kotlin
authenticate("heliumid") {
    requireScope("workspace:read")  { get("/api/documents") { … } }
    requireScope("workspace:read", "workspace:write") { post("/api/documents") { … } }
}
```

Both axes apply at once. A caller holding `workspace:write` still cannot edit a document they only
view, and a document owner whose token lacks `workspace:write` still cannot write through this API.

Grab the access token from the Session page and try it:

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/documents
```

Verification is offline: the `HeliumId` plugin checks the ES256 signature against the cached JWKS,
so there is no round trip per request. The cost is revocation latency — a revoked token keeps
verifying until it expires, at most five minutes. Turn on `introspection { enabled = true }` in
`Application.kt` if that is too long.

---

## Other SDK features on show

Discovery and JWKS, `userInfo()`, refresh-token rotation with serialized access per session,
`revoke()` on sign-out, and the typed `HeliumError` hierarchy — including `MfaRequired` and
`ReauthenticationRequired` as ordinary states rather than exceptions.

**Tokens never reach the browser.** The cookie carries a signed, opaque session id; access and
refresh tokens live only in the server-side session. The Session page renders the access token
because this is a demo — a real application would not.

**Refreshes are serialized per session** (`Session.kt`, `refreshLock`). Refresh tokens rotate and
HeliumID treats a token presented twice as theft: it revokes the whole family and signs the user
out everywhere. Two concurrent requests both noticing an expiring token would do exactly that.

---

## What the client has to get right itself

**`state` and `nonce` are the relying party's job.** HeliumID accepts an authorization request
without either and never checks them, so a client that omits them has no CSRF protection on the
callback and no replay protection on the ID token. This app generates both, keeps them server-side
behind an opaque handle, and consumes the handle exactly once. `docs/threat-model.md` §3 claims
both are required server-side; they are not.

**ID-token verification is the client's job too.** The SDK's server plugin verifies *access*
tokens, which is a resource server's role. An ID token is a statement made to *this* client, and
`auth/IdTokenVerifier.kt` checks signature, issuer, audience, expiry and — the part that matters —
that the `nonce` matches this sign-in.

---

## Tests

```bash
./gradlew test
```

27 tests, no running HeliumID required — the SDK is driven against a mock engine and the ID-token
suite signs its own tokens against an in-memory key set. They cover the document permission matrix,
login-transaction single use and expiry, ID-token rejection (bad nonce, wrong issuer, wrong
audience, expired, unknown signing key), and the callback's refusals (state mismatch, missing
state, replayed handle, no pending login, non-local `return_to`).

---

## Known gaps in HeliumID, as of this example

Findings from building against it. The first three were fixed as part of this work; the rest are
open.

**Fixed**

- **The consent screen was unreachable for third-party clients.** `infra/Caddyfile.dev` routed all
  of `/oauth2/*` to the backend, which answers `GET /oauth2/authorize` with a JSON consent prompt —
  so a browser rendered raw JSON and the SPA's `ConsentPage` never ran. Now routed by `Accept`.
- **Scopes could not be created.** Only `GET /v1/admin/scopes` existed, and client registration
  rejects unknown scopes, so the catalogue was frozen at whatever `V2__reference_data.sql` seeded.
  `PUT` and `DELETE /v1/admin/scopes/{name}` were added, with built-in scopes and in-use scopes
  refused.
- **`Pkce.generateState()` and `Pkce.generateNonce()` always threw.** Both delegated to
  `generateVerifier(24)`, whose `32..96` guard rejected the call unconditionally. Neither could
  ever return a value — and they are precisely the two defences the point above says the client
  must supply.

**Open**

- **RP-initiated logout does not exist.** Discovery advertises `end_session_endpoint` as
  `{issuer}/oauth2/logout`; there is no such route and it 404s. This app signs out locally and
  revokes the refresh token, which is the part that is actually available.
- **Consent cannot be revoked.** `ConsentRepository` is wired into `HeliumApi` but no route uses
  it, so a user cannot withdraw an approval they granted.
- **The first-party API ignores scopes.** `/v1/me` and `/v1/admin` authorize on the user's
  permissions and never look at the token's `scope`, and incoming bearer tokens are verified with
  no expected audience. So any client the user has consented to — even one holding only `openid` —
  can call `/v1/admin` with that user's full permissions. Scopes bound what this application may
  do on *its own* API; they bound nothing on HeliumID's.
