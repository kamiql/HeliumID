# syntax=docker/dockerfile:1.7
#
# HeliumID backend image.
#
# Two runnable targets, `dev` and `prod`, both fed by a single `build` stage. That matters more
# than it looks: if dev and prod compiled separately, the thing you debug and the thing you ship
# would be different artifacts, and "works in dev" would stop being evidence of anything. Here
# the only differences are the JVM flags, the user, and whether a debugger port is open.
#
#   docker build --target dev  -t helium-id:dev  backend
#   docker build --target prod -t helium-id:prod backend

# --- build -------------------------------------------------------------------------------------
#
# The Gradle image only supplies a JDK 25 and a sane HOME; the wrapper decides the Gradle version
# (9.6.1, pinned in gradle-wrapper.properties) so a container build and a laptop build resolve the
# same toolchain. Letting the image's own `gradle` win would make CI and local drift silently.
FROM gradle:9-jdk25 AS build

# Run the build as root and keep GRADLE_USER_HOME at a fixed absolute path. Both are about the
# BuildKit cache mount below: it has to be writable by whichever user the base image happens to
# default to, and its target has to be the directory Gradle actually caches into. Relying on the
# image's `gradle` user and its $HOME couples this file to an upstream detail that has changed
# before.
USER root
ENV GRADLE_USER_HOME=/gradle-home

WORKDIR /workspace

# Dependency metadata first. Gradle's caches live in the cache mount, but the layer split still
# pays: editing a .kt file does not invalidate the wrapper download.
COPY gradlew gradlew.bat gradle.properties settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle

# Warm the wrapper. `--no-daemon` because a daemon that outlives the RUN step is pure overhead in
# a container.
#
# The chmod and the CR strip are both for Windows checkouts. The executable bit does not survive,
# and a `gradlew` with CRLF endings has the shebang `#!/bin/sh\r`, which Linux reports as
# `./gradlew: not found` — a message that blames the script rather than its line endings.
# `.gitattributes` pins this to LF at the repository level; this line makes the build survive a
# clone made before that existed.
RUN --mount=type=cache,target=/gradle-home \
    sed -i 's/\r$//' ./gradlew && chmod +x ./gradlew && ./gradlew --no-daemon --version

COPY . .

# `installDist` rather than a fat jar: it lays out `bin/helium-id` plus a `lib/` directory, so the
# dependency jars land in their own image layer and a code-only change re-uploads kilobytes instead
# of the whole shaded artifact. It also keeps the classpath inspectable, which matters when you are
# auditing what actually shipped.
#
# Tests are deliberately not run here. CI runs them; a release build that silently reruns them is
# slower and gives a worse signal than a pipeline that fails on its own test job.
#
# The copy into /opt happens inside this RUN so both runtime targets can `COPY --from=build` one
# fixed path, without either of them having to know how Gradle lays out `app/build/install`. The
# `test -x` turns a silently-renamed launcher into a build failure instead of a container that
# starts and immediately exits 127.
RUN --mount=type=cache,target=/gradle-home \
    ./gradlew --no-daemon --stacktrace :app:installDist \
 && cp -r app/build/install/helium-id /opt/helium-id \
 && test -x /opt/helium-id/bin/helium-id

# --- runtime base ------------------------------------------------------------------------------
#
# JRE, not JDK: no compiler, no jshell, no attach tooling in the production image. Shrinking the
# toolset an attacker inherits after RCE is cheap, so there is no reason not to.
FROM eclipse-temurin:25-jre AS runtime

# curl is here for one reason: HEALTHCHECK. Docker's healthcheck runs a command *inside* the
# container, so the image has to be able to talk to itself. Everything else from the base image
# stays untouched.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# A fixed uid/gid, not just a name. Bind mounts and volumes are matched by numeric id on the host,
# so pinning it keeps file ownership predictable across rebuilds and across hosts.
RUN groupadd --system --gid 10001 helium \
 && useradd --system --uid 10001 --gid helium --home-dir /opt/helium-id --shell /usr/sbin/nologin helium

COPY --from=build --chown=root:root /opt/helium-id /opt/helium-id

ENV PATH="/opt/helium-id/bin:${PATH}" \
    HELIUM_HTTP_PORT=8080 \
    HELIUM_HTTP_HOST=0.0.0.0
EXPOSE 8080

# Container-aware defaults. Without MaxRAMPercentage the JVM sizes the heap from the *host's*
# memory on some kernels and gets OOM-killed the moment the cgroup limit bites. 75% leaves room
# for metaspace, code cache, thread stacks and Netty's direct buffers.
#
# UseContainerSupport is on by default on 25; it is spelled out because someone will eventually
# add a flag here and needs to see what is already assumed.
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError -Djava.security.egd=file:/dev/urandom -Duser.timezone=UTC -Dfile.encoding=UTF-8"

# --- dev ---------------------------------------------------------------------------------------
FROM runtime AS dev

# JDWP on 5005, bound to 0.0.0.0 so the debugger can reach it from the host.
#
# `suspend=n` so a forgotten debugger does not wedge the stack on `docker compose up`. This target
# must never be deployed: an open JDWP port is remote code execution by design, which is exactly
# why it is a separate target rather than an env toggle on the prod image.
#
# ShowCodeDetailsInExceptionMessages turns NPEs into something you can act on. It is off in prod
# because those messages can name fields and values, and this codebase handles secrets.
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:+ShowCodeDetailsInExceptionMessages -Duser.timezone=UTC -Dfile.encoding=UTF-8 -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005" \
    HELIUM_ENV=dev
EXPOSE 5005

# No USER here: dev stays root, on purpose. You will want to `docker compose exec` and install
# something, and the threat model of a laptop stack whose debugger port is already open is not
# improved by dropping privileges. The prod target below does drop them.

HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=12 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/opt/helium-id/bin/helium-id"]

# --- prod --------------------------------------------------------------------------------------
FROM runtime AS prod

# Non-root, and the install tree stays owned by root: the process can read its own code but cannot
# rewrite it. That turns "attacker got code execution in the JVM" into a strictly harder problem
# than "attacker persisted a backdoor in /opt".
USER 10001:10001

# start-period is generous because the first boot pays for connection-pool warmup and, when
# HELIUM_MIGRATE_ON_START is on, Flyway. An impatient healthcheck restarts the container mid
# migration, which is the one thing you never want to do to a schema change.
HEALTHCHECK --interval=15s --timeout=3s --start-period=90s --retries=5 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/opt/helium-id/bin/helium-id"]
