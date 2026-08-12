# syntax=docker/dockerfile:1.7
#
# HeliumID frontend image.
#
# Same shape as the backend: one dependency install, two targets. `dev` runs the Vite dev server
# behind Caddy with working HMR; `prod` is a build-only image whose entire job is to hand the
# compiled assets to Caddy and exit.

FROM node:24-alpine AS deps

WORKDIR /app

# `npm ci` and not `npm install`: ci installs exactly the lockfile and fails if package.json and
# the lock have drifted. In an image build that is the behaviour you want — a silent dependency
# bump is a supply-chain change, and this project ships security-critical code.
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci

# --- dev ---------------------------------------------------------------------------------------
FROM deps AS dev

# The dev server listens on 90 *inside the container*, matching the host port Caddy is published
# on. That is the whole HMR trick: Vite tells the browser which port to open the websocket on, and
# the browser is talking to localhost:90. Make the two agree and HMR works through the proxy with
# no `server.hmr.clientPort` in vite.config.ts — which matters here, because that file belongs to
# the frontend work, not to the deployment layer.
#
# --strictPort so a port collision fails loudly instead of Vite quietly picking 91 and leaving you
# with a dev server nobody can reach.
ENV NODE_ENV=development
EXPOSE 90
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "90", "--strictPort"]

# --- build -------------------------------------------------------------------------------------
FROM deps AS build

COPY . .

# `npm run build` is `tsc -b && vite build`: a type error fails the image build rather than
# shipping a bundle that only fails at runtime.
RUN --mount=type=cache,target=/root/.npm \
    npm run build

# --- prod --------------------------------------------------------------------------------------
#
# Not a server. Caddy serves the assets; this image exists so the bundle is built reproducibly in
# CI instead of depending on whatever Node version the deploy host happens to have, and so a stale
# `frontend/dist` on disk can never be what production is serving.
#
# It runs once, copies the bundle into the shared volume Caddy reads, and exits 0. Compose gates
# Caddy on that exit with `service_completed_successfully`.
FROM alpine:3.21 AS prod

RUN addgroup -g 10002 -S web && adduser -u 10002 -S -G web web

COPY --from=build /app/dist /dist

# /srv has to exist in the image *and* be owned by the unprivileged user. Docker seeds an empty
# named volume from the image's content at the mount point, ownership included; without this the
# volume would be created root-owned and the copy below would fail with EACCES.
RUN mkdir -p /srv && chown web:web /srv

USER 10002:10002

# `/srv/.` rather than `/srv`: copy the *contents*, so re-running does not nest dist inside dist.
# The delete pass first means a removed asset actually disappears — otherwise old hashed bundles
# accumulate in the volume forever and a rollback silently serves a mix of two builds.
CMD ["sh", "-c", "rm -rf /srv/* && cp -a /dist/. /srv/ && echo 'frontend assets published to /srv'"]
