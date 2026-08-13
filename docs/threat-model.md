# HeliumID threat model

Scope: the HeliumID authorization server, its account API, the SPA it serves, and the deployment
described by `docker-compose.prod.yml`.

This document is a working artefact, not a certificate. It records what was considered and what
was done about it, so a reviewer can tell the difference between a threat that was mitigated and a
threat that was never thought about. **HeliumID has not been externally audited** — see the
residual-risk section, and see §9.1 of the concept document, quoted in the README, on why running
Keycloak or Zitadel instead is usually the correct engineering decision.

---

## 1. Assets

Ranked by what an attacker gains, not by how much code touches them.

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Signing key private halves | `signing_keys`, AES-GCM encrypted under the current data key | Forging an access token is equivalent to authenticating as anyone, anywhere the token is accepted. This is the crown jewel. |
| Data-encryption keys (`HELIUM_DATA_KEYS`) | Secret manager / process environment | Decrypts signing keys and TOTP secrets. Compromise chains straight to the row above. |
| Token HMAC key (`HELIUM_TOKEN_HMAC_KEY`) | Secret manager / process environment | Refresh tokens, session handles, reset and verification tokens are stored as HMACs. With the key, a database dump becomes a set of usable credentials. |
| Password hashes and the pepper | `credentials`, secret manager | Offline cracking; credential reuse against other services. |
| TOTP secrets and recovery codes | `mfa_factors`, encrypted / hashed | Defeats the second factor, which is the control every recovery flow leans on. |
| Passkey public keys and credential ids | `webauthn_credentials`, plaintext | Deliberately *not* an asset in the same sense. The private key never leaves the authenticator, so a full dump lets an attacker verify signatures, never produce them. What has to be protected is the relying-party *configuration*, not the rows — see "Real-time phishing and MFA relay" in §3. |
| Refresh tokens and session handles | `sessions`, `refresh_tokens` (hashed) | Long-lived authentication. |
| Trusted-device tokens | `trusted_devices` (hashed) | Waives the MFA challenge at login for the configured window. Weaker than a session handle — it still requires the password — but it is the one credential that lowers authentication assurance. |
| Client secrets | `oauth_clients` (hashed) | Impersonating a confidential client; obtaining tokens for its scopes. |
| Audit log | `audit_events` | The record of what happened. An attacker who can edit it can erase the incident. |
| PII: email addresses, usernames, IPs, user agents | `users`, `sessions`, `audit_events` | Disclosure and enumeration harm independent of account compromise. |

## 2. Trust boundaries

```
 ┌─────────┐   ①    ┌───────┐   ②    ┌──────────┐   ③    ┌────────────┐
 │ browser ├───────►│ Caddy ├───────►│ backend  ├───────►│ PostgreSQL │
 │ / app   │  TLS   │ edge  │  HTTP  │ (Ktor)   │  TCP   │   Redis    │
 └─────────┘        └───────┘        └────┬─────┘        └────────────┘
                                          │ ④
                                          ▼
                              external IdPs, SMTP, webhooks
```

1. **Internet → edge.** Fully untrusted. Every byte, including every `X-Forwarded-*` header.
2. **Edge → backend.** The edge is the only thing allowed to assert client IP and protocol. It
   *overwrites* `X-Forwarded-For` with the real peer rather than appending, because the backend
   reads the leftmost entry and keys rate limits on it. Appending would let a caller supply the
   first entry and mint a fresh identity per request.
3. **Backend → data.** Not published outside the compose network in production. The database
   account owns every hash and every audit row; a published port is one firewall mistake away from
   a full dump.
4. **Backend → outbound.** External identity providers, SMTP, webhooks. Responses are untrusted
   input, and destinations are allowlisted — see SSRF below.

The SPA is **not** a trust boundary. It runs on the user's machine, so nothing it enforces counts;
every check it performs exists for user experience and is repeated server-side.

---

## 3. Threats and mitigations

### Spoofing

**Account enumeration.** Registration, login, password reset and email resend all return the same
response and the same rough latency whether or not the identity exists. Reset and verification
always report "if that address exists, we sent a link"; login failures never distinguish unknown
user from wrong password. Argon2id verification runs against a dummy hash for unknown users, so
the timing side channel closes too. Rate limits are keyed on both identifier and IP, so an attacker
cannot enumerate faster than the limit whatever signal they think they have found. *Never reveal
whether a username or email exists* is a CLAUDE.md invariant, and it constrains error codes as much
as error text.

**Credential stuffing and brute force.** Argon2id, benchmarked in the deployment environment, makes
each guess expensive by design. Layered limits (concept §4.6): per identifier, per IP, per client,
with progressive delays and account lockout thresholds. Limits live in Redis so they hold across
instances, with an in-memory fallback that fails *closed* per instance rather than disabling the
limit. `auth_login_failures_total` and `rate_limit_rejections_total` make the attempt visible.

**Real-time phishing and MFA relay.** A password plus a TOTP code can both be relayed: the attacker
puts up a convincing page, the user types both, and the attacker replays them within the code's
window. Nothing about TOTP prevents this, because the user is the transport. Passkeys are the
answer to that specific attack, and HeliumID offers them as a **second factor** — the first factor
is still the password.

* **Origin and RP-ID binding.** The browser scopes a credential to the configured relying-party id
  and will only release an assertion to a page whose origin the server has allowlisted
  (`HELIUM_WEBAUTHN_RP_ID`, `HELIUM_WEBAUTHN_ORIGINS`). The lookalike domain never obtains an
  assertion at all, so there is nothing to relay. This is the whole mitigation, which is why the
  configuration is validated at startup rather than trusted: the rp id must be the host of every
  configured origin or a parent of it, non-`https` origins are refused outside loopback, and a
  loopback origin is refused in production. An rp id broader than it needs to be — `example.com`
  for a service on `app.example.com` — extends assertion-minting to every sibling subdomain, so a
  subdomain takeover would become an authentication bypass. The process refuses to start on that
  configuration instead of warning about it.
* **Single-use challenges.** Every registration and authentication challenge is at least 128 bits,
  stored server-side, redeemable exactly once, and expires in two minutes. A captured ceremony
  cannot be replayed, and the challenge is consumed atomically so two concurrent redemptions
  cannot both succeed.
* **Cloned-authenticator detection.** Authenticators report a signature counter that must strictly
  advance. A counter that repeats or goes backwards is the signal that a credential has been
  copied off the device; the assertion is rejected rather than tolerated. Authenticators that
  report a constant zero — most synced platform passkeys — are exempt by specification, so this
  detects cloned *hardware* keys and nothing else. It is a signal, not a boundary.
* **Nothing secret is stored.** The private key never leaves the authenticator. `webauthn_credentials`
  holds public keys and credential ids in the clear because a dump of it lets an attacker verify
  signatures, never produce them — the opposite of the TOTP row above, which is encrypted precisely
  because it *is* a shared secret.
* **Removal is a high-severity audit event.** Deleting a second factor is the most valuable action
  available to somebody holding a stolen session, so `account.mfa.webauthn.remove` pages alongside
  `account.mfa.totp.disable`. Audit metadata never carries credential ids, public keys, challenges
  or signatures.

Recovery codes remain a shared secret and remain phishable; a deployment that wants the phishing
resistance end to end has to be willing to make account recovery an administrative action.

**Session fixation.** A session identifier is never carried across an authentication state change.
Login issues a brand-new session; MFA completion, password change and step-up reauthentication each
rotate it. The pre-authentication MFA transaction is a separate one-time object with its own short
TTL and is consumed on use, so a handle observed before authentication is worthless after it.

**Provider-linking takeover.** The classic attack: register at an external IdP with the victim's
email address, sign in, and get silently linked to their account. HeliumID never links by email —
a CLAUDE.md invariant and concept §9.4. Linking an external identity requires an authenticated
session and an explicit, one-time linking transaction. `email_verified` from a provider is treated
as a claim about that provider's records, not as proof the user controls the mailbox. Unlinking the
last authentication method is refused, so linking can never be used to strand an account.

**Client impersonation.** Client secrets are stored hashed. Public clients hold no secret and are
required to use PKCE S256. Redirect URIs are matched exactly — no prefix matching, no wildcard
subdomains, no ignored query strings — because every relaxation of that rule has a published
exploit behind it.

### Tampering

**CSRF.** Four independent layers, because each has a known bypass alone (concept §4.5, implemented
in `api-http/HttpSecurity.kt`): `SameSite=Lax` cookies; `Sec-Fetch-Site` checking; `Origin`
checking against the allowlist; and a double-submit token compared with `MessageDigest.isEqual`.
Bearer-authenticated requests skip the token check, correctly — a browser will not attach an
`Authorization` header cross-site. Safe methods are exempt because they change no state, which is
an invariant the route layer has to keep true.

**Cookie tampering and theft.** Session cookies are `HttpOnly`, `Secure`, `SameSite=Lax`, and carry
the `__Host-` prefix, which makes the browser enforce `Secure` + `Path=/` + no `Domain`. A
misconfiguration then produces a cookie the browser refuses rather than one it silently accepts.
`HELIUM_SECURE_COOKIES=false` drops both the flag and the prefix together and exists only for
local HTTP development. The CSP set by the edge (`frame-ancestors 'none'`, `form-action 'self'`,
`object-src 'none'`) is the browser-side half; the server-side half is that no cookie is a
capability on its own.

**Audit-log tampering.** Audit rows are append-only from the application's perspective: no update
or delete path exists in the repository. Records are written in the same transaction as the state
change they describe, so a rollback cannot leave a false record and a committed change cannot leave
no record.

### Repudiation

Structured audit events for authentication, authorization, MFA, provider linking, client changes
and administrative actions, each with actor, subject, client, IP, user agent, outcome and
correlation id. Written transactionally with the change. Retention and soft deletion rather than
immediate hard deletion for security data (concept §3.4), so an attacker cannot erase their trail
by deleting the account.

### Information disclosure

**Secrets in logs.** Passwords, bearer tokens, cookies, authorization codes, TOTP values, reset
tokens and raw provider responses are never logged (CLAUDE.md, concept §7.5). `Secret` and
`PasswordHash` override `toString()` to redact, so an accidental interpolation prints
`PasswordHash(argon2id, redacted)` rather than the value — the defence does not depend on every
future log statement being written carefully.

The audit trail gets the same treatment and needs it more, because it is retained rather than
rotated. Flow metadata is assembled from flow state, so a step only has to name a key carelessly
for the value to be written to `audit_events` permanently. Keys holding a secret are marked
sensitive and excluded from the snapshot, and `audit-risk/AuditMetadataPolicy` applies a central
denylist on top: credential ids, public keys, challenges, signatures, attestation and client-data
blobs, and any oversized value are replaced with `[redacted]` before the row is written. The key
is kept so the suppression itself is visible to whoever reads the trail.

**Secrets in images and metrics.** `.dockerignore` excludes `.env*` and key material from both
build contexts, so nothing can be baked into a layer. Metrics carry no email addresses or usernames
as labels (concept §7.5), which is both a cardinality and a disclosure concern. `/metrics` is not
exposed through the production edge.

**Error-message leakage.** RFC 9457 problem documents with stable machine-readable codes.
Production returns the code and a generic title; stack traces and internal detail stay in the log.
`ShowCodeDetailsInExceptionMessages` is enabled in the dev image target only, because those
messages can name fields and values.

**Database at rest.** TOTP secrets and stored signing keys are AES-GCM encrypted under a versioned
data key, with the version stored beside the ciphertext so keys can rotate without a big-bang
re-encryption. Refresh tokens, session handles, email tokens and recovery codes are stored as
HMACs, never in the clear.

### Denial of service

Rate limits on every authentication path. Argon2id parameters bounded and benchmarked — a
memory-hard KDF is also a memory-hard *self*-DoS if concurrency is unbounded, which is why the
container memory limit and `HELIUM_ARGON2_MEMORY_KIB` are documented as a pair. Connection-pool
limits keep the database from being the failure point. Outbox delivery runs in a separate worker,
so an unreachable SMTP server delays mail instead of consuming request threads. Log rotation is
configured because an identity provider whose disk fills up stops writing audit records.

Fail-closed on token validation, MFA verification and authorization checks (concept §7.6): when a
dependency is unavailable, requests are refused, not allowed.

### Elevation of privilege

**Authorization.** Every state-changing flow declares its requirements explicitly — authentication,
reauthentication, MFA, email verification, permission, idempotency. Requirements are typed and
evaluated by the flow engine, not by ad-hoc checks in route handlers, so "someone forgot the check"
is a missing declaration rather than an invisible omission. Routes translate HTTP into commands and
map results back; they contain no security policy.

**Privilege escalation through roles.** Role and permission changes are administrative operations
requiring `admin:role:write`, and they are audited. Built-in roles are flagged as such and cannot
be redefined out from under the permission checks.

**Token substitution and confusion.** Access tokens carry issuer, audience and client id, and all
three are validated. Service principals get scopes only and no user permissions, so a client
credentials token can never act as a user. Revoked tokens are checked against a deny list on every
request, because signature validity and expiry alone would let a revoked token keep working until
it expired.

**Scope escalation.** Consent is recorded per client and per scope. A token is never issued for a
scope the client is not registered for, nor for one the user has not consented to; a refresh
exchange cannot widen scope.

### Protocol-specific

**Token replay and refresh-token reuse.** Refresh tokens are single-use and rotate on every
exchange. Presenting a previously rotated token is treated as a compromise signal, not an error:
the entire token family is revoked, `auth_refresh_reuse_detected_total` increments, and the user is
notified. This is the one control that turns a stolen refresh token from indefinite access into a
detectable, bounded incident. See the runbook in `docs/operations.md`.

**Trusted-device MFA exemption.** A device on which a second factor was verified may skip the
challenge on later password logins for `HELIUM_TRUSTED_DEVICE_DAYS` (default 30, `0` disables).
This is a deliberate, and the only, reduction in authentication assurance in the system, so it is
worth stating precisely what it does and does not weaken.

The exemption is a 256-bit value in an `HttpOnly`, `__Host-`-prefixed cookie, stored only as an
HMAC and bound to the account — lookups are keyed on `(user_id, hash)`, so a token minted for one
account cannot be replayed into another. It is explicitly *not* built on the user-agent/IP
fingerprint used for new-sign-in notifications: both of those inputs are attacker-supplied, which
is acceptable for a notification and disqualifying for a control.

Four properties bound the loss:

* **The session tells the truth.** A login that skipped the factor records only `pwd` in its `amr`,
  never `otp`. Every step-up operation — password change, MFA management, admin actions — therefore
  still demands a real factor. The exemption buys past the login prompt and nothing else.
* **Privileged accounts are excluded.** Any principal holding a permission in
  `Permission.STEP_UP_REQUIRED` is challenged regardless, and their cookie is not even examined.
* **It rotates, and reuse is detected.** Each use issues a successor and retains one superseded
  generation. Presenting the old value means the cookie was copied off the machine: the device is
  revoked and the owner notified, in an independent transaction so the response survives the
  challenge that unwinds the login. Same mechanism and same reasoning as refresh-token reuse.
* **It is revoked on every signal that matters.** Password change, password reset, any MFA change,
  admin suspension or forced sign-out, account deletion, and explicit user revocation from the
  device list.

Residual risk, stated plainly: an attacker with both the password and the unlocked machine gets in
without the second factor, for up to the configured window. That is the trade being made. Where it
is unacceptable, set `HELIUM_TRUSTED_DEVICE_DAYS=0`.

**Authorization-code replay.** Codes are one-time, short-lived, bound to the client and to the
redirect URI, and consumed atomically by a conditional update — so two concurrent redemptions
cannot both succeed.

**PKCE downgrade.** `code_challenge_method=S256` is required; `plain` is rejected. A code issued
with a challenge cannot be redeemed without the verifier, and the verifier is compared after
hashing.

**Nonce and state.** `state` is required and bound to the browser session for CSRF on the
authorization request. OIDC `nonce` is required and matched against the ID token, which is what
stops an ID token obtained elsewhere from being replayed here.

**Open redirect.** `redirect_uri` must match a registered value exactly. Post-logout and
post-authentication return URLs are validated against the same allowlist. Arbitrary callback URLs
are rejected — a CLAUDE.md invariant, and the reason there is no "just this once" escape hatch in
the code.

**SSRF via provider configuration.** Provider endpoints are configured, never discovered from
user-controlled input. Google's endpoints are hard-coded rather than fetched, because a discovery
document is one more remote input and a moving target; where discovery *is* used, the returned
`issuer` must equal the configured one before anything else is trusted. Issuers are an allowlist:
an ID token from any other issuer is rejected however validly it is signed. Redirects are not
followed on provider token exchanges, and outbound calls have explicit timeouts.

**JWT algorithm confusion.** ES256 with EC P-256. `alg: none` and HMAC algorithms are rejected at
parse time, not by trusting the header's claim about how to verify itself. `kid` resolves to a key
that is currently publishable; retired keys stop verifying.

---

## 4. Deployment-level threats

| Threat | Mitigation |
| --- | --- |
| Container escape to host root | Production image runs as uid 10001 with the install tree owned by root — the process can read its code but cannot rewrite it. JRE, not JDK: no compiler or attach tooling to inherit. |
| Exposed database | No published ports for Postgres or Redis in `docker-compose.prod.yml`; reachable only on the compose network. |
| Debugger in production | JDWP exists only in the `dev` image target and is bound to loopback there. An open JDWP port is unauthenticated RCE, so it is a separate build target rather than a flag on the production image — no environment variable can turn it on. |
| Secrets in the image | `.dockerignore` excludes `.env*`, `*.pem`, `*.key`, `*.p12`, `*.jks` from both build contexts. |
| Secrets in source control | `.env.dev` / `.env.prod` are gitignored; the committed `.example` files contain only placeholders. Production values belong in a secret manager (concept §7.1). |
| Stale frontend in production | The bundle is built inside Docker by the one-shot `frontend-assets` service, not bind-mounted from a developer's `dist/`. |
| Unreviewed migration at boot | `HELIUM_MIGRATE_ON_START=false` in production; migrations are an explicit release step. |
| Supply chain | `npm ci` installs exactly the lockfile; the Gradle wrapper pins the build tool version. CI dependency scanning is required by CLAUDE.md step 1. |

---

## 5. Residual risks and out of scope

Stated plainly, because a threat model that only lists solved problems is marketing.

**No external audit.** No penetration test, no cryptographic review, no bug-bounty history. Every
mitigation above is self-assessed. The protocol implementations are written from specifications and
tested against the abuse cases the authors thought of, which is a strictly smaller set than the one
that exists.

**Not implemented yet.** These are milestones, not omissions with mitigations:

* **Passwordless passkey login** — a passkey is a *second* factor here, never a first one. Signing
  in still starts with a password. This is a deliberate scope decision, not an oversight: a
  first-factor passkey makes the authenticator the account, so losing the phone becomes losing the
  account, and the recovery path that replaces it is the new weakest link — an email-based
  passkey reset would hand back exactly the phishability the passkey was bought to remove. That
  needs its own recovery design (attested enrolment, multiple registered authenticators, an
  out-of-band verification channel) and it is a separate milestone.
* **LDAP and SAML federation** — no enterprise directory or SAML SP/IdP support.
* **SCIM** — no automated user provisioning or deprovisioning. An offboarded employee is removed
  only as fast as an administrator removes them.
* **Multi-tenancy** — one realm, one user namespace, one policy set (concept §9.7). Isolating
  tenants after the fact is a schema change, not a configuration change.
* **DPoP, PAR, mTLS client authentication, JARM** — access tokens are bearer tokens. Anyone who
  obtains one can use it until it expires or is revoked; there is no proof-of-possession binding.
* **Token exchange (RFC 8693) and client-initiated backchannel authentication.**

**Accepted as out of scope.**

* **HSM-backed signing.** Private keys are encrypted at the application layer with a key from the
  environment, not held in an HSM or cloud KMS that never releases them. A compromise that yields
  both the database and the process environment yields the signing keys.
* **Key management infrastructure.** `HELIUM_DATA_KEYS` in the environment is the interface.
  Wiring it to Vault or a cloud KMS is deployment work this repository does not do for you, and
  concept §7.1 says plainly that the environment is not where production secrets should live.
* **Infrastructure security.** Host hardening, network policy, TLS termination, WAF, DDoS
  protection, container-image scanning and OS patching are the operator's.
* **Insider threat.** Anyone with production database access plus the key material has everything.
  The audit log records administrative actions but is not tamper-evident against someone with
  direct database access.
* **Compromised external identity providers.** If Google's token endpoint is compromised, accounts
  linked to Google are compromised. Signature and issuer validation do not help against a valid
  signature from the legitimate issuer.
* **Client-side compromise.** Malware, a malicious browser extension, or XSS in a *relying party*
  application. The CSP and cookie flags raise the cost; they do not solve it.
* **Email as a recovery channel.** Password reset relies on email, so an attacker with mailbox
  access can reset the password. MFA remains required after reset, which is what keeps mailbox
  compromise from being full account takeover — but it makes the second factor load-bearing.

**Known sharp edges.**

* Argon2id parameters must be benchmarked per deployment. The shipped values are a starting point
  from concept §4.1, and a value copied from a document is a guess, not a decision.
* Rate limiting degrades to per-instance in-memory counters if Redis is unavailable, which raises
  the effective global limit by roughly the number of instances.
* `HELIUM_TRUST_FORWARDED_HEADERS=true` is only safe behind a proxy that overwrites
  `X-Forwarded-For`. The bundled Caddyfiles do; a different edge may not, and the failure is
  silent — every per-IP limit simply stops working.
