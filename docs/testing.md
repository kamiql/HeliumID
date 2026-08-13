# Testing

Four layers, each answering a question the one below it cannot.

| Layer | Where | Command | Needs Docker |
| --- | --- | --- | --- |
| Unit | every module's `src/test` | `./gradlew test` | no |
| Protocol / repository | `persistence-postgres`, `persistence-redis`, `protocol-oauth2-oidc` | `./gradlew integrationTest` | yes |
| Route inventory | `api-http` | `./gradlew :api-http:test` | no |
| End-to-end | `app` | `./gradlew :app:integrationTest` | yes |

`./gradlew build` runs everything that does not need a container. Container-backed suites are
tagged `integration` and excluded from `test`, so a developer without Docker still gets a green
build and a useful signal — they just do not get the whole one.

## Running the container-backed suites

```sh
cd backend && ./gradlew integrationTest
```

Two things commonly go wrong on Windows, and the root `build.gradle.kts` has an escape hatch for
each:

* **Testcontainers cannot find the daemon.** It probes a fixed list of endpoints and ignores the
  active Docker CLI context, so Docker Desktop's named pipe is invisible to it. Pass
  `-PdockerHost='npipe:////./pipe/dockerDesktopLinuxEngine'`, or export `DOCKER_HOST`.
* **Docker Engine 29 rejects the negotiated API version**, answering `/info` with a `400` that
  Testcontainers reports as "no Docker environment". Pass `-PdockerApiVersion=1.51`, or export
  `DOCKER_API_VERSION`.

The PostgreSQL container is started once per JVM and shared; suites truncate between tests rather
than restarting it. Opt into reuse across runs by setting `testcontainers.reuse.enable=true` in
`~/.testcontainers.properties`.

## Unit tests use fakes, deliberately

Module tests wire fakes and drive a flow directly. They are the right tool for state that is
fiddly to arrange over HTTP — a token that expired between two steps, a concurrent update losing a
conditional `UPDATE`, a provider returning a malformed assertion — and they stay fast enough to
run on every save.

What they cannot do is tell you whether the *assembled* server behaves. A fake satisfies a
requirement that the real session service would refuse; a repository nobody passed to the
composition root is a compile error only if something references it.

## The end-to-end layer

`app/src/test/.../support/` boots the production object graph — `HeliumComponents`, the same one
`main()` builds — against the real database, and drives it over HTTP with `testApplication`.

Four things are deliberately not production-shaped, each for a stated reason in
`HeliumTestApp`'s KDoc: Redis is absent (so the in-memory limiter and transaction store are used),
Argon2 runs at a low work factor, `secureCookies` is off because the test transport is plain HTTP,
and there is no SMTP server.

### Reading mail

There is no mailbox. Verification and reset tokens exist only in transit — the database holds a
hash — so tests recover them from the transactional outbox through `OutboxReader`. This is also
why CLAUDE.md's "notifications are outbox effects, never inline side effects" rule is load-bearing
rather than aspirational here: if a flow sent mail inline, these tests would stop finding tokens.

### Actors

`Actors.create()` registers over HTTP, reads the token out of the outbox and redeems it, so every
test that needs a signed-in user exercises registration as a side effect. The single exception is
granting `ADMINISTRATOR`, which is a direct repository write because no route creates the *first*
administrator — that is `DevBootstrap`'s job, and it is deliberately unreachable over the network.

### State that truncation does not reset

The component graph is a JVM singleton, so anything it holds in memory outlives a test.
`HeliumTestApp.reset()` therefore clears the rate limiter as well as truncating the database.
Without that, every request in the suite arrives from the same loopback address and the per-IP
limits treat the whole run as one client — `RateLimit.REGISTRATION` is five per hour, and because
registration answers `202` whether or not it succeeded, the sixth account would silently fail to
exist and surface much later as an inexplicable `401` at login.

## Route coverage

Two checks, in two modules, that together make it hard to add an endpoint nobody looks at.

**`RouteInventoryTest` (`api-http`, no container)** walks the Ktor routing tree and compares it to
[`docs/api-routes.md`](api-routes.md). The document is generated, never hand-edited:

```sh
cd backend && ./gradlew :api-http:test --tests '*RouteInventoryTest*' -Dhelium.routes.write=true
```

**`RouteCoverageTest` (`app`, container)** then requires every route in that document to be
reached by an end-to-end test. Requests go through `HeliumTestClient`, which takes a route
*template* plus its parameters — `http.delete("/v1/me/sessions/{sessionId}", "sessionId" to id)` —
and records the template. Matching a concrete path back to a template afterwards would be a second
routing implementation that can disagree with Ktor's; asking for the template means the census
measures rather than infers.

So: a new endpoint fails the inventory until it is documented, and fails the census until it is
tested.

`RouteCoverageTest.NOT_YET_EXERCISED` is a ratchet, not an exemption list. Coverage arrived after
the API did, so the routes that had no end-to-end test on that day are written down with a reason
each. The test fails in both directions — an uncovered route outside the list, *and* a listed
route that is now covered — so the list can only shrink. Deleting the last entry deletes the
mechanism.

Because the census counts what the JVM executed, running a filtered subset (`--tests …`) fails it
by construction. That is the census correctly reporting that most routes went untouched; run the
whole `:app:integrationTest` before believing a failure.

## What a change is expected to bring

CLAUDE.md's definition of done asks for tests covering success, failure, retry, replay,
concurrency and authorization boundaries. In practice:

* a new **flow** — unit tests for every requirement and step, with fakes;
* a new **repository method** — an integration test, because the behaviour under test is usually a
  partial index, a conditional `UPDATE` or a `timestamptz` comparison that only PostgreSQL has;
* a new **route** — a regenerated `docs/api-routes.md` and at least one end-to-end test, including
  the negative case: enumeration, authorization boundary, CSRF, or replay, whichever applies.
