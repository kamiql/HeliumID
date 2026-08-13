# HeliumID

# VERSION 2 IS A PROOF OF CONCEPT TO EXPERIMENT WITH CLAUDE CODE

A standards-based identity and authorization provider written in Kotlin and Ktor: local accounts,
OAuth 2.0 / OpenID Connect, external identity providers, TOTP, WebAuthn passkeys as a second
factor, and an account API for web, SPA, native and subsidiary applications.

---

> ### Read this before you deploy it
>
> **If identity is not your product, use something else.** Keycloak, Zitadel and ORY Hydra are
> mature, audited, and maintained by people whose full-time job is exactly this. Concept §9.1 is
> blunt about why: the hard parts of an authorization server are not password hashing and JWT
> signing. They are redirect-URI validation, consent and scope semantics, PKCE, refresh-token
> replay, OIDC nonce handling, client authentication, logout semantics, key rotation, provider
> federation, account linking, recovery flows that resist takeover, back-channel effects, and the
> long tail of browser security behaviour. Each of those has a published CVE history written by
> people who thought about it more carefully than a first implementation will.
>
> **HeliumID has not been audited.** It is security-critical code written from a specification —
> not code with a pentest report and a disclosure history behind it. It is a reasonable choice if
> identity *is* the thing you are building, if you intend to own it long-term, and if you will pay
> for a review before it holds real accounts. It is a bad choice if you want SSO and want to stop
> thinking about it.
>
> The right shape for most projects: run a proven authorization server, and implement only your
> domain-specific account API in Ktor.

---

## What is in here

PostgreSQL is the source of truth. Redis holds expiring state — rate-limit windows, short-lived
security transactions, locks — and correctness never depends on it surviving. Email, webhooks and
notifications are transactional outbox effects delivered by a separate worker, never inline side
effects of a database transaction.

### Module map

Ports and adapters, enforced by dependency declarations rather than by review: the domain modules
never declare a Ktor, JDBC, Redis or provider-SDK dependency, so importing one is a compile error.

| Module | Responsibility |
| --- | --- |
| `auth-domain` | Users, credentials, external identities, sessions, MFA factors, clients, policies, domain events. No framework imports. |
| `flow-engine` | Typed requirements, steps, transactions, effects, idempotency, hooks. |
| `provider-spi` | The port every external identity provider implements. |
| `identity-flows` | Registration, login, MFA, password and email change, provider linking, admin operations. |
| `protocol-oauth2-oidc` | Authorization, token, revocation, introspection, discovery, JWKS, PKCE, signing keys. |
| `provider-oidc` | Generic OIDC adapter; Google preconfigured. |
| `mfa-totp` | TOTP enrolment, challenge, recovery codes. |
| `mfa-webauthn` | WebAuthn ceremony verification for passkeys used as a second factor. |
| `security-crypto` | Argon2id, HMAC token hashing, AES-GCM envelope encryption, key provider. |
| `persistence-postgres` | Exposed repositories, Hikari, Flyway migrations, audit and outbox tables. |
| `persistence-redis` | Rate limiter and security-transaction store, each with an in-memory fallback. |
| `api-http` | Ktor routes, DTOs, RFC 9457 error mapping, CSRF, principal resolution. |
| `audit-risk` | Security events, rate limits, risk signals. |
| `jobs` | Outbox delivery, cleanup, key rotation, notification retry. |
| `app` | Composition root and `main`. |
| `helium-client` | Consumer-facing client library. |
| `test-support` | Shared fixtures and Testcontainers helpers. |

The frontend is a React + Vite SPA under `frontend/`. In both dev and prod it is served from the
same origin as the API, because cookie scope, SameSite, CSRF and the OAuth redirect allowlist are
all origin-scoped — a split-origin dev setup would quietly exercise a different security
configuration than the one that ships.

---

## Running it

Both stacks put the whole system behind Caddy on **host port 90**.

### Development

```sh
cp .env.dev.example .env.dev
docker compose --env-file .env.dev -f docker-compose.dev.yml up --build
```

| | |
| --- | --- |
| Application | <http://localhost:90> |
| Captured mail (Mailpit) | <http://localhost:90/mail>, also <http://localhost:8025> |
| Backend, bypassing Caddy | <http://localhost:8080> |
| Metrics | <http://localhost:90/metrics> |
| PostgreSQL | `localhost:5432` |
| Redis | `localhost:6379` |
| JVM debugger (JDWP) | `localhost:5005` — attach any time, the process does not wait |

The SPA runs under the Vite dev server with HMR working through the proxy. Frontend edits are
picked up from the bind mount; backend edits need a rebuild:

```sh
docker compose --env-file .env.dev -f docker-compose.dev.yml up -d --build backend
```

Flyway runs at startup in dev (`HELIUM_MIGRATE_ON_START=true`) and a single administrator is
bootstrapped from `HELIUM_BOOTSTRAP_ADMIN_*` — both only because `HELIUM_ENV=dev`.

`--env-file` is not optional. It is what compose uses for `${...}` interpolation; the `env_file:`
entries inside the compose file are a separate mechanism that only populates container
environments.

### Production

```sh
cp .env.prod.example .env.prod
# fill every REQUIRED value from your secret manager, then:
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --build

# migrations are a separate, deliberate step — see docs/operations.md
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  run --rm -e HELIUM_MIGRATE_ON_START=true -e HELIUM_ROLE=migrate backend
```

Differences from dev, all deliberate:

* no published database or cache ports — Postgres and Redis exist only on the compose network;
* the backend runs as a non-root user from the `prod` image target, with no debugger;
* migrations do not run at boot (concept §3.4);
* outbox delivery runs in a separate `worker` container, so slow SMTP cannot starve request
  threads;
* `/metrics` is not reachable through the edge;
* healthchecks, restart policies, log rotation and resource ceilings on every service.

The prod edge listens on plain HTTP and assumes **TLS terminates in front of it**. Serving an
identity provider over HTTP to real browsers is not an option: `Secure` cookies are dropped, the
`__Host-` prefix is refused, and redirect URIs stop being trustworthy. Either put an ingress in
front, or change the site address in `infra/Caddyfile.prod` from `:80` to your hostname and let
Caddy obtain a certificate itself.

The frontend bundle is built inside Docker by the one-shot `frontend-assets` service and published
into a volume Caddy mounts read-only, so production can never be serving whatever a developer last
compiled locally.

### Without Docker

```sh
cd backend
./gradlew :app:installDist    # launcher at app/build/install/helium-id/bin/helium-id
./gradlew build               # compile + unit and protocol suites (fast, no Docker needed)
./gradlew integrationTest     # Testcontainers-backed suites, opt-in
```

Container-backed suites are tagged `integration` and excluded from `build` on purpose, so the
common loop stays fast and works offline. What each layer is for — and why a new route needs both
a regenerated route inventory and an end-to-end test — is in
[`docs/testing.md`](docs/testing.md).

**Docker Desktop on Windows.** Testcontainers probes a fixed list of daemon endpoints and does
not read the active Docker CLI context, and Docker Engine 29 rejects the older Engine API
versions `docker-java` negotiates by default — the symptom of either is
`Could not find a valid Docker environment` even though `docker info` works. Both are
overridable:

```sh
./gradlew integrationTest -PdockerApiVersion=1.44
./gradlew integrationTest -PdockerHost='npipe:////./pipe/dockerDesktopLinuxEngine'
```

`DOCKER_API_VERSION` and `DOCKER_HOST` in the environment work too, and take precedence.

---

## Endpoints

Protocol endpoints sit at the root, where the specifications require them; the account API is
versioned under `/v1`. Through the edge the account API is additionally reachable under `/api`
(the prefix is stripped before proxying), while protocol paths are proxied verbatim — a discovery
document advertising `/api/oauth2/authorize` would simply be wrong.

The tables below are grouped for reading. The **authoritative** list is
[`docs/api-routes.md`](docs/api-routes.md), which is generated from the Ktor routing tree rather
than maintained by hand — these tables had drifted from the code before it existed, and a route
that is registered but undocumented is a route nobody reviews.

### OAuth 2.0 / OpenID Connect

| Method | Path |
| --- | --- |
| `GET` | `/.well-known/openid-configuration` |
| `GET` | `/.well-known/jwks.json` |
| `GET` | `/oauth2/authorize` |
| `POST` | `/oauth2/token` |
| `POST` | `/oauth2/revoke` |
| `POST` | `/oauth2/introspect` |
| `GET` | `/userinfo` |

Authorization Code with PKCE S256 is the primary flow for SPA and native clients. The Resource
Owner Password Credentials grant is not implemented and will not be.

### Authentication

| Method | Path |
| --- | --- |
| `GET` | `/v1/auth/session` |
| `GET` | `/v1/auth/password-requirements` |
| `POST` | `/v1/auth/register` |
| `POST` | `/v1/auth/login` — first-party / BFF only, not a replacement for `/oauth2/authorize` |
| `POST` | `/v1/auth/mfa/challenge` — issues the WebAuthn request options for a pending MFA transaction |
| `POST` | `/v1/auth/mfa/verify` — accepts either a `code` (TOTP or recovery code) or a `webauthn` assertion |
| `POST` | `/v1/auth/logout` |
| `POST` | `/v1/auth/email/verify`, `/v1/auth/email/resend` |
| `POST` | `/v1/auth/password-reset/request`, `/v1/auth/password-reset/complete` |
| `GET` | `/v1/auth/providers` |
| `GET` | `/v1/auth/providers/{provider}/start`, `/v1/auth/providers/{provider}/callback` |

Passkeys are a **second** factor, not a replacement for the password. `/v1/auth/login` runs first
and returns an MFA challenge; `/v1/auth/mfa/challenge` turns that challenge into
`PublicKeyCredentialRequestOptions`; `/v1/auth/mfa/verify` consumes the resulting assertion in place
of a `code`. Passwordless passkey sign-in is deliberately out of scope and the reasoning is recorded
in [`docs/threat-model.md`](docs/threat-model.md) §5.

The relying party is configured with `HELIUM_WEBAUTHN_RP_ID`, `HELIUM_WEBAUTHN_RP_NAME` and
`HELIUM_WEBAUTHN_ORIGINS`. That binding is what makes a passkey phishing-resistant, so it is
validated at startup: the rp id must be the host of every configured origin or a parent of it,
origins must be `https` outside loopback, and the process refuses to start otherwise.

### Account

| Method | Path |
| --- | --- |
| `GET` / `PUT` | `/v1/me` |
| `PUT` | `/v1/me/password` |
| `POST` | `/v1/me/email-change`, `/v1/me/email-change/confirm` |
| `POST` | `/v1/me/delete` |
| `GET` / `DELETE` | `/v1/me/sessions`, `/v1/me/sessions/{sessionId}` |
| `GET` / `DELETE` | `/v1/me/trusted-devices`, `/v1/me/trusted-devices/{id}` |
| `GET` | `/v1/me/mfa` |
| `POST` | `/v1/me/mfa/totp/enroll`, `/v1/me/mfa/totp/confirm`, `/v1/me/mfa/totp/disable` |
| `POST` | `/v1/me/mfa/webauthn/enroll`, `/v1/me/mfa/webauthn/confirm`, `/v1/me/mfa/webauthn/remove` |
| `POST` | `/v1/me/mfa/recovery-codes` |
| `GET` / `DELETE` | `/v1/me/providers`, `/v1/me/providers/{provider}` |
| `GET` / `DELETE` | `/v1/me/authorizations`, `/v1/me/authorizations/{clientId}` |

`/v1/me/providers` and `/v1/me/authorizations` point in opposite directions: the first lists the
external identities you sign in *with*, the second the OAuth clients that hold access *to* your
account. The second is assembled from stored consents *and* live refresh-token families, so a
first-party client registered with `skip_consent` is listed too — it has access either way.
Revoking drops the consent and kills every refresh-token family for that client; access tokens it
already holds stay valid for the remainder of their short lifetime. Revoking something that was
never granted, belongs to someone else, or is already gone all answer `404`.

### Administration

Every route requires an `admin:*` permission.

| Method | Path |
| --- | --- |
| `GET` | `/v1/admin/users`, `/v1/admin/users/{userId}` |
| `PUT` | `/v1/admin/users/{userId}/status`, `/v1/admin/users/{userId}/roles` |
| `GET` | `/v1/admin/users/{userId}/sessions` |
| `POST` | `/v1/admin/users/{userId}/revoke-sessions` |
| `GET` | `/v1/admin/roles`, `/v1/admin/permissions`, `/v1/admin/scopes` |
| `PUT` / `DELETE` | `/v1/admin/roles/{name}` |
| `PUT` / `DELETE` | `/v1/admin/scopes/{name}` |
| `GET` | `/v1/admin/clients`, `/v1/admin/clients/{clientId}` |
| `POST` | `/v1/admin/clients`, `/v1/admin/clients/{clientId}/rotate-secret` |
| `PATCH` / `DELETE` | `/v1/admin/clients/{clientId}` |
| `GET` | `/v1/admin/audit` |

Nearly every write here declares `ReauthenticatedWithin`, which a bearer principal can never
satisfy — automating them means driving a browser session, as `examples/demo-app/Setup.kt` does.
The exceptions are session revocation and scope CRUD.

### Operational

| Method | Path | |
| --- | --- | --- |
| `GET` | `/health` | Liveness. Deliberately uninformative — a probe that names the failing dependency is a reconnaissance endpoint. |
| `GET` | `/health/ready` | Readiness. `503` until the database answers. |
| `GET` | `/metrics` | Prometheus. Through the edge in dev only — scrape counters leak login volumes, failure rates and client identifiers. |

Errors follow RFC 9457 with stable machine-readable codes (concept §5.3–§5.5).

---

## Documentation

* [`docs/threat-model.md`](docs/threat-model.md) — assets, trust boundaries, threats and the
  mitigation implemented for each, plus what is explicitly out of scope.
* [`docs/operations.md`](docs/operations.md) — key rotation, migration policy, backups, the
  refresh-token-reuse runbook, and the metric and log field reference.
* [`docs/testing.md`](docs/testing.md) — the four test layers, what belongs in each, and the
  route-coverage ratchet.
* [`docs/api-routes.md`](docs/api-routes.md) — every HTTP route, generated from the routing tree.
* `CLAUDE.md` — the security invariants and architectural rules this codebase is held to.

## Configuration

Every variable is documented in `.env.dev.example` and `.env.prod.example`. Neither contains a real
secret and neither ever should. Production secrets belong in a secret manager (concept §7.1); a
`.env` on the deploy host is the weakest acceptable option, because it is readable by anything that
can read the filesystem, survives in backups, and shows up in `docker inspect`.
