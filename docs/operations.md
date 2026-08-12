# HeliumID operations

Runbooks for the things that will actually wake someone up. Every command assumes the production
compose file; shorten it if you like:

```sh
alias hc='docker compose --env-file .env.prod -f docker-compose.prod.yml'
```

---

## 1. Key rotation

Three kinds of key, three different procedures, three different blast radii. Confusing them is how
a routine rotation becomes an outage.

| Key | Rotate when | Blast radius if done wrong |
| --- | --- | --- |
| Token signing keys (EC P-256) | Quarterly, or on suspicion | Clients reject valid tokens |
| Data-encryption keys (`HELIUM_DATA_KEYS`) | Annually, or on suspicion | TOTP enrolments become undecryptable — unrecoverable |
| Token HMAC key (`HELIUM_TOKEN_HMAC_KEY`) | On suspicion only | Every session and refresh token invalidated at once |

### 1.1 Signing keys (concept §7.2)

The `kid` is what makes this safe. Verifiers pick the key by `kid`, so the new and old keys coexist
and nothing has to be atomic.

1. **Generate.** A new key is created in `PENDING` and stored encrypted under the current data key.
   ```sh
   hc exec backend helium-id keys signing generate
   ```
2. **Publish.** `PENDING` keys appear in `/.well-known/jwks.json` but do not sign yet. Wait long
   enough for every relying party to refresh its JWKS cache — an hour is typical, but check what
   your clients actually do, because a client that caches for 24 hours will reject tokens for 24
   hours if you skip this.
   ```sh
   curl -s https://id.example.com/.well-known/jwks.json | jq '.keys[].kid'
   ```
3. **Promote.** New tokens are signed with the new `kid`; the old key moves to `RETIRING` and keeps
   verifying.
   ```sh
   hc exec backend helium-id keys signing promote --kid auth-signing-key-2026-08-<epoch>
   ```
4. **Wait out the old tokens.** Access-token TTL plus a margin. Keeping a retiring key published
   costs nothing; retiring it early breaks live sessions.
5. **Retire.** The key stops being published and stops verifying.
   ```sh
   hc exec backend helium-id keys signing retire --kid <old-kid>
   ```

**Emergency revocation.** If a private key is believed compromised, skip the waiting: promote a new
key, retire the old one immediately, and revoke outstanding tokens. Every access token signed by
the retired key becomes invalid at once, which is the intended outcome — clients re-authenticate.
Record the incident in the audit log with the reason.

### 1.2 Data-encryption keys

The one procedure where the order genuinely matters. **A key version can never be removed from
`HELIUM_DATA_KEYS` while any ciphertext still references it.** Remove it and you have destroyed
the TOTP enrolment of every user who has not logged in since — there is no recovery, only
re-enrolment.

1. Generate: `openssl rand -base64 32`
2. **Append** it, keeping every existing version:
   ```
   HELIUM_DATA_KEYS=1:<old>,2:<new>
   HELIUM_DATA_KEY_VERSION=1      # still 1
   ```
3. Deploy. Every instance can now *decrypt* version 2 but still *writes* version 1.
4. Verify the whole fleet is on the new configuration. This is the step people skip.
5. Bump the write version and deploy again:
   ```
   HELIUM_DATA_KEY_VERSION=2
   ```
6. Re-encrypt. Ciphertext is upgraded lazily on read, or eagerly with:
   ```sh
   hc exec worker helium-id keys data reencrypt --to-version 2
   ```
7. Confirm nothing references the old version, then and only then drop it:
   ```sh
   hc exec backend helium-id keys data usage
   ```

### 1.3 Token HMAC key

Rotating this invalidates every stored token hash at once: sessions, refresh tokens, pending email
verifications, pending password resets, unused recovery codes. Everyone is logged out and every
in-flight reset link stops working.

That is the correct response to a suspected key compromise and a bad idea for routine hygiene. If
you do it: announce it, do it in a maintenance window, and expect a support spike from users whose
reset links died mid-flow.

---

## 2. Migrations

Flyway, forward-only, one version per change. `HELIUM_MIGRATE_ON_START=false` in production
(concept §3.4): replicas restarting after a crash would race Flyway's lock, and an
expand-and-contract migration has to land *between* two deploys by definition, which a
migrate-on-boot deployment cannot express.

### Policy

* Every schema change is versioned. No manual DDL — a hand-applied change makes the next
  `validateOnMigrate` fail and you will fix it under time pressure.
* Prefer expand-and-contract: add nullable column → deploy code writing both → backfill → switch
  reads → remove the old representation in a *later* release. Four deploys, no downtime, and every
  step is individually revertible.
* Never delete security data immediately. Retention and soft deletion (concept §3.4) — an attacker
  should not be able to erase evidence by deleting an account.
* Test against the production PostgreSQL version. `postgres:17-alpine` in both compose files is
  there so dev, CI and prod agree.
* `baselineOnMigrate` is off deliberately: pointing Flyway at a non-empty database it does not know
  should fail loudly, not assume the schema is already right.

### Applying

```sh
# 1. back up first — see §3
hc exec postgres pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB" > pre-migration.dump

# 2. dry run: what would be applied?
hc run --rm -e HELIUM_ROLE=migrate backend helium-id migrate info

# 3. apply, with the application still on the previous version
hc run --rm -e HELIUM_MIGRATE_ON_START=true -e HELIUM_ROLE=migrate backend

# 4. deploy the application
hc up -d --build backend worker
```

### Rollback

There is no `flyway undo`. Rollback is forward-fix: write a new migration that reverses the change,
or restore from the pre-migration dump and replay. Which one applies depends on whether the
migration was expand-shaped (reversible by a new migration) or destructive (restore only) — decide
that *before* applying, and write it in the PR.

---

## 3. Backups

**What must be backed up:** the PostgreSQL volume, and the key material in the secret manager.
Neither is useful without the other. A backup you cannot decrypt is not a backup, and a restore
drill that skips the key-manager side is not a drill.

**What must not:** Redis. It holds rate-limit windows and short-lived security transactions only,
and correctness never depends on it — persistence is disabled precisely so nobody is tempted to
treat it as durable.

```sh
# nightly, encrypted at rest, off-host
hc exec -T postgres pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB" \
  | age -r "$BACKUP_RECIPIENT" > "helium-$(date -u +%Y%m%dT%H%M%SZ).dump.age"
```

* Retention: 30 daily, 12 monthly. Audit data has its own, longer retention in-database.
* **The dump contains password hashes, encrypted TOTP secrets and the full audit log.** Treat it
  with the same care as the database. Encrypted at rest, access-logged, never on a laptop.
* Restore drill quarterly, into a scratch environment, using the *current* key material. An
  untested restore is a hypothesis.
* Point-in-time recovery needs WAL archiving, which this compose file does not configure. If your
  recovery point objective is smaller than "last night", use a managed PostgreSQL and delete the
  `postgres` service.

---

## 4. Runbook: refresh-token reuse detected

**Signal:** `auth_refresh_reuse_detected_total` increments; an audit event of type
`refresh_token.reuse_detected` appears with the user, client and token family.

**What it means.** A refresh token that had already been rotated was presented again. Refresh
tokens are single-use, so exactly one of two things is true: either a token was stolen and the
thief is now racing the legitimate client, or a client retried an exchange after a network failure
without persisting the rotated token.

**Automatic response**, already taken by the time you read the alert:

1. The entire token family is revoked — every descendant of the original grant.
2. All sessions derived from that family are terminated.
3. A security notification is queued to the user through the outbox.
4. An audit event is written.

**Manual triage:**

1. Confirm the blast radius.
   ```sh
   hc exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
     "select occurred_at, client_id, ip_address, user_agent, outcome
        from audit_events
       where subject_user_id = '<user-id>'
         and occurred_at > now() - interval '7 days'
       order by occurred_at desc limit 100;"
   ```
2. **Two distinct IPs or user agents in the family → treat as compromise.** One client, one IP,
   clustered in time → most likely a buggy client retrying. The distinguishing question is whether
   the two redemptions could plausibly be the same device.
3. If compromise: revoke everything for the user, force a password reset, and require MFA
   re-enrolment if the second factor could also have been captured.
   ```sh
   hc exec backend helium-id user revoke-sessions --user <user-id>
   hc exec backend helium-id user force-password-reset --user <user-id>
   ```
4. Check whether the same client id is producing reuse across *many* users. One user is an
   incident; many users is a compromised client or a leaked client secret, and the client secret
   should be rotated:
   ```sh
   hc exec backend helium-id client rotate-secret --client <client-id>
   ```
5. If a client secret or key material was involved, rotate it (§1) and record the decision.

**Do not** disable reuse detection to stop the alerts. A misbehaving client is a bug in the client;
turning off the detector converts a detectable incident into an undetectable one.

---

## 5. Other runbooks, briefly

**Outbox backing up** (`outbox_delivery_failures_total` climbing). Almost always SMTP. Check
`hc logs worker`; verify `HELIUM_SMTP_*`; confirm the provider is not rate-limiting you. Entries
are retried with backoff and are not lost, so the user impact is delayed verification mail rather
than failed registrations — which is exactly why delivery is an outbox effect and not an inline
side effect.

**Creating the first administrator.** No account is seeded by any migration: a credential in a
migration is a credential in source control and in every deployment that ever runs it.
`HELIUM_BOOTSTRAP_ADMIN_*` only applies when `HELIUM_ENV=dev`. In production:

```sh
hc run --rm backend helium-id admin create --email ops@example.com --username ops
```

The generated password is printed once, to stdout, and an audit record is written. Change it and
enrol MFA immediately.

**Provider outage.** External IdP failures are contained by timeouts and a circuit breaker; local
credential login continues to work. Watch `provider_latency_seconds` and
`oauth_callback_failures_total`.

**Suspected total compromise.** Rotate signing keys with immediate retirement (§1.1), rotate the
token HMAC key to invalidate every session (§1.3), rotate the database password and every client
secret, then preserve the audit log before anything else — it is the only record of what happened,
and it is the first thing that becomes ambiguous once you start changing things.

---

## 6. Metrics reference (concept §7.5)

Prometheus at `/metrics` on port 8080. Exposed through the edge in dev only: scrape counters leak
login volumes, failure rates and client identifiers, so scrape the backend directly on the internal
network in production.

| Metric | Type | Watch for |
| --- | --- | --- |
| `auth_login_attempts_total` | counter | Baseline for the ratio below |
| `auth_login_failures_total` | counter | Failure ratio above ~30% sustained → credential stuffing |
| `auth_mfa_challenges_total` | counter | A sudden drop can mean MFA is being bypassed, not that users stopped using it |
| `auth_refresh_reuse_detected_total` | counter | **Any** non-zero value is an incident — see §4 |
| `oauth_callback_failures_total` | counter | Provider outage, or a misconfigured redirect URI after a deploy |
| `password_hash_duration_seconds` | histogram | p50 outside 100–300 ms → re-benchmark Argon2id |
| `provider_latency_seconds` | histogram | Rising p99 precedes callback failures |
| `rate_limit_rejections_total` | counter | A spike is either an attack or a limit set too tight |
| `outbox_delivery_failures_total` | counter | Sustained non-zero → mail is not reaching users |

**Label discipline.** Never use raw email addresses or usernames as labels — unbounded cardinality
will take down the metrics backend, and it puts identifiers somewhere with a very different access
policy from the database. `client_id` and `provider` are bounded and safe. Outcome labels are
coarse (`success` / `failure` / `challenge`) on purpose: a per-error-code breakdown of login
failures is an enumeration oracle for anyone who can read the metrics.

## 7. Log field reference (concept §7.5)

JSON in production (`HELIUM_LOG_FORMAT=json`).

| Field | Meaning |
| --- | --- |
| `timestamp` | UTC, ISO-8601 |
| `request_id` | Per request; echoed to the client so a user's report can be correlated to a log line |
| `trace_id` | Distributed trace, when tracing is wired up |
| `event_type` | `auth.login`, `oauth.token.issued`, `mfa.challenge.completed`, … |
| `client_id` | OAuth client, when there is one |
| `user_id` | Internal identifier. **Never** the email address or username |
| `outcome` | `success`, `failure`, `challenge` |
| `provider` | External IdP, for federation events |
| `latency_ms` | Server-side handling time |
| `ip_address` | From `X-Forwarded-For` only when `HELIUM_TRUST_FORWARDED_HEADERS=true` |

**Never logged**, at any level, in any environment: passwords, bearer tokens, refresh tokens,
cookies, TOTP codes, recovery codes, reset and verification tokens, authorization codes, client
secrets, full OAuth provider responses. This is a CLAUDE.md invariant. `Secret` and `PasswordHash`
redact themselves in `toString()`, so an accidental interpolation prints
`PasswordHash(argon2id, redacted)` — the defence does not rely on every future log statement being
written carefully, which is the only kind of defence that survives a codebase growing.

`HELIUM_LOG_LEVEL=DEBUG` in production is a liability: debug logging attracts exactly the category
of data that must never reach the log pipeline.
