#!/usr/bin/env bash
#
# Brings up the Helium demo workspace and runs it in the foreground.
#
#   ./run-demo.sh
#
# Every step is skipped when it is already done, so this is safe to re-run. What it does, in
# order: start the HeliumID dev stack, publish the SDK to mavenLocal, register the demo's scopes
# and OAuth client, then hand the terminal over to the application.
#
# The one genuinely awkward part is the client secret. HeliumID shows it exactly once, at
# registration, and cannot read it back — so this script caches it in `.demo-secret` and, when
# that cache is stale (a reset database, a rotated secret, a deleted file), recovers by rotating
# the secret rather than failing. See `resolve_secret`.
#
# Flags:
#   --reset      delete and re-register the OAuth client before starting (costs two sign-ins,
#                against a limit of five per account per ten minutes)
#   --no-stack   never touch docker; fail if HeliumID is not already reachable
#   --republish  force `publishToMavenLocal` even when the SDK is present
#   --setup-only do everything except starting the application
#

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$APP_DIR/../.." && pwd)"
SECRET_FILE="$APP_DIR/.demo-secret"

# Defaults mirror DemoConfig.kt. Override any of them in the environment.
ISSUER="${HELIUM_ISSUER:-http://localhost:90}"
ISSUER="${ISSUER%/}"
BASE_URL="${DEMO_BASE_URL:-http://localhost:8081}"
BASE_URL="${BASE_URL%/}"
PORT="${DEMO_PORT:-8081}"
CLIENT_ID="${DEMO_CLIENT_ID:-helium-demo}"
ADMIN_USER="${HELIUM_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${HELIUM_ADMIN_PASSWORD:-dev-only-change-me}"

RESET=0
NO_STACK=0
REPUBLISH=0
SETUP_ONLY=0

COOKIE_JAR=""

# Results of the functions below. They are globals, and deliberately so: a function whose value
# is captured with `$(…)` runs in a subshell, where `die` can only kill the subshell — the caller
# sails on with an empty string and fails later, twice, with the wrong message. Anything that can
# fail therefore returns through a variable and is called as a plain statement.
CSRF=""
NEW_SECRET=""
SECRET=""

# `return 0` is load-bearing: this runs as an EXIT trap, and a falsy last command here would
# become the script's exit status — turning a clean --setup-only or --help into a failure.
cleanup() { [ -n "$COOKIE_JAR" ] && rm -f "$COOKIE_JAR"; COOKIE_JAR=""; return 0; }
trap cleanup EXIT

# One jar for the whole run, allocated here in the top-level shell. The functions that need an
# administrator session are called inside command substitutions, and a path created down there
# would neither be visible to the next call nor survive to be cleaned up.
COOKIE_JAR="$(mktemp)"

# --- output ---------------------------------------------------------------------------

if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; OFF=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; YELLOW=""; GREEN=""; OFF=""
fi

step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
info() { printf '    %s%s%s\n' "$DIM" "$*" "$OFF"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '    %s!%s %s\n' "$YELLOW" "$OFF" "$*" >&2; }
die()  { printf '\n%serror:%s %s\n\n' "$RED" "$OFF" "$*" >&2; exit 1; }

usage() { sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^#\s\?//'; exit 0; }

# Pulls one string field out of a JSON object, or nothing when it is absent. The responses this
# touches are small and flat, so a real parser would only add a dependency (jq is not a given on
# Windows).
#
# The trailing `|| true` matters under `set -o pipefail`: a grep that matches nothing exits 1,
# which would abort the caller before it could report a decent error about the missing field.
json_field() {
    grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed -E 's/.*"([^"]*)"$/\1/' || true
}

# --- arguments ------------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --reset)      RESET=1 ;;
        --no-stack)   NO_STACK=1 ;;
        --republish)  REPUBLISH=1 ;;
        --setup-only) SETUP_ONLY=1 ;;
        -h|--help)    usage ;;
        *)            die "unknown option '$1'. Try --help." ;;
    esac
    shift
done

command -v curl >/dev/null 2>&1 || die "curl is required."

# --- 1. the HeliumID dev stack ----------------------------------------------------------

issuer_up() { curl -fsS --max-time 3 "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; }

wait_for_issuer() {
    local waited=0 limit="${1:-120}"
    while ! issuer_up; do
        [ "$waited" -ge "$limit" ] && return 1
        sleep 2
        waited=$((waited + 2))
        [ $((waited % 10)) -eq 0 ] && info "still waiting for $ISSUER … ${waited}s"
    done
    return 0
}

ensure_stack() {
    step "HeliumID at $ISSUER"

    if issuer_up; then
        ok "already up"
        return
    fi

    if [ "$NO_STACK" -eq 1 ]; then
        die "not reachable, and --no-stack was given."
    fi

    command -v docker >/dev/null 2>&1 || die "not reachable, and docker is not on PATH."

    if [ ! -f "$ROOT_DIR/.env.dev" ]; then
        info "creating .env.dev from .env.dev.example"
        cp "$ROOT_DIR/.env.dev.example" "$ROOT_DIR/.env.dev"
    fi

    info "starting the dev stack (first build takes a few minutes)"
    ( cd "$ROOT_DIR" && docker compose --env-file .env.dev -f docker-compose.dev.yml up -d --build )

    wait_for_issuer 180 || die "the stack started but $ISSUER never answered. Check: docker compose -f docker-compose.dev.yml logs"
    ok "up"
}

# --- 2. the SDK in mavenLocal -----------------------------------------------------------

ensure_sdk() {
    # Read the version the build actually asks for, so the two cannot drift apart.
    local version
    # `|| true` so that a miss falls through to the check below rather than aborting on pipefail.
    version="$(grep -oE 'dev\.kamiql\.helium:helium-client:[^"]+' "$APP_DIR/build.gradle.kts" | head -1 | cut -d: -f3 || true)"
    [ -n "$version" ] || die "could not read the helium-client version from build.gradle.kts."

    step "helium-client $version in mavenLocal"

    local repo="${HOME}/.m2/repository/dev/kamiql/helium/helium-client/$version"
    if [ -d "$repo" ] && [ "$REPUBLISH" -eq 0 ]; then
        ok "present"
        return
    fi

    info "publishing from backend/"
    ( cd "$ROOT_DIR/backend" && ./gradlew :helium-client:publishToMavenLocal --console=plain -q )
    ok "published"
}

# --- 3. the OAuth client ----------------------------------------------------------------

# True when this secret authenticates as $CLIENT_ID.
#
# Presents a deliberately bogus refresh token: client authentication is checked before the grant
# is, so `invalid_grant` means the secret was accepted and `invalid_client` means it was not.
# It is the only read-back of a secret HeliumID offers, and it needs no admin session.
secret_works() {
    [ -n "${1:-}" ] || return 1
    curl -sS --max-time 5 -X POST "$ISSUER/oauth2/token" \
        --data-urlencode "grant_type=refresh_token" \
        --data-urlencode "refresh_token=probe-not-a-real-token" \
        --data-urlencode "client_id=$CLIENT_ID" \
        --data-urlencode "client_secret=$1" 2>/dev/null \
        | grep -q "invalid_grant"
}

# Whether the client is registered, and whether it will accept our redirect URI — answered
# without credentials, and so without spending one of the five sign-ins HeliumID allows per
# account per ten minutes. The authorization endpoint separates the three cases cleanly:
#
#   302  registered, and $BASE_URL/callback is one of its redirect URIs
#   400  registered, but this redirect URI is not
#   403  unauthorized_client — no such client
#
# Knowing this up front is what keeps a run to a single sign-in: without it the script would have
# to guess, register, and fall back to rotating, logging in twice on the common path.
client_state() {
    # Any syntactically valid S256 challenge; the request is never completed.
    local probe="3q5soefAlKaqbOj7nfnDeOY4dw8VJbHNIVy4F_793Ck"
    local status
    status="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -G "$ISSUER/oauth2/authorize" \
        --data-urlencode "response_type=code" \
        --data-urlencode "client_id=$CLIENT_ID" \
        --data-urlencode "redirect_uri=$BASE_URL/callback" \
        --data-urlencode "scope=openid" \
        --data-urlencode "state=probe" \
        --data-urlencode "code_challenge=$probe" \
        --data-urlencode "code_challenge_method=S256" 2>/dev/null || true)"

    case "$status" in
        302) printf 'present' ;;
        400) printf 'redirect-mismatch' ;;
        *)   printf 'missing' ;;
    esac
}

# Signs in as the administrator, leaving a session in $COOKIE_JAR and a fresh token in $CSRF.
#
# Registration and rotation both sit behind ReauthenticatedWithin(5 min), which rejects every
# principal that is not a browser session — a client_credentials token cannot satisfy it however
# privileged it is. So this does what a browser does, including re-reading the CSRF token, which
# the server rotates on authentication.
admin_login() {
    : >"$COOKIE_JAR"   # discard anything left by a previous call

    local csrf status body
    csrf="$(curl -sS -c "$COOKIE_JAR" "$ISSUER/v1/auth/session" | json_field csrf_token)"
    [ -n "$csrf" ] || die "no CSRF token from $ISSUER/v1/auth/session."

    # Escape the two characters that would otherwise break out of a JSON string. A password is
    # arbitrary text and there is no reason it cannot contain a quote or a backslash.
    local json_user json_pass
    json_user="$(printf '%s' "$ADMIN_USER" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
    json_pass="$(printf '%s' "$ADMIN_PASS" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"

    body="$(mktemp)"
    status="$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o "$body" -w '%{http_code}' \
        -X POST "$ISSUER/v1/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: $csrf" \
        --data-raw "{\"identifier\":\"$json_user\",\"password\":\"$json_pass\"}")"

    if [ "$status" != "204" ]; then
        local detail; detail="$(cat "$body")"; rm -f "$body"
        case "$detail" in
            *mfa_required*) die "the '$ADMIN_USER' account has MFA enabled and this script cannot answer a challenge.
       Register the client by hand at $ISSUER (Admin → Clients), or use an account without a second factor." ;;
            *rate_limited*) die "HeliumID is rate-limiting sign-ins — 5 per account per 10 minutes, and this run used one.
       Wait a few minutes and try again. Once .demo-secret is cached, re-runs need no sign-in at all." ;;
            *) die "sign-in failed for '$ADMIN_USER' (HTTP $status): $detail
       Set HELIUM_ADMIN_USERNAME and HELIUM_ADMIN_PASSWORD to the bootstrap administrator from .env.dev." ;;
        esac
    fi
    rm -f "$body"

    # Re-read: authentication rotated it, and everything that follows is state-changing.
    CSRF="$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$ISSUER/v1/auth/session" | json_field csrf_token)"
    [ -n "$CSRF" ] || die "signed in, but no CSRF token came back from $ISSUER/v1/auth/session."
}

# Mints a replacement secret for an existing client, into $NEW_SECRET.
rotate_secret() {
    admin_login
    local response
    response="$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
        -H "X-CSRF-Token: $CSRF" \
        -X POST "$ISSUER/v1/admin/clients/$CLIENT_ID/rotate-secret")"
    NEW_SECRET="$(printf '%s' "$response" | json_field secret)"
    [ -n "$NEW_SECRET" ] || die "could not rotate the secret for '$CLIENT_ID': $response"
}

delete_client() {
    admin_login
    local status
    status="$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -o /dev/null -w '%{http_code}' \
        -H "X-CSRF-Token: $CSRF" \
        -X DELETE "$ISSUER/v1/admin/clients/$CLIENT_ID")"
    case "$status" in
        204|404) ;;
        *) die "could not delete '$CLIENT_ID' (HTTP $status)." ;;
    esac
}

# Runs `./gradlew setup`, which registers the scopes and the client. Leaves the minted secret in
# $NEW_SECRET, or leaves it empty when the client already existed.
run_gradle_setup() {
    local out status
    NEW_SECRET=""
    out="$(mktemp)"
    set +e
    ( cd "$APP_DIR" && HELIUM_ISSUER="$ISSUER" DEMO_BASE_URL="$BASE_URL" DEMO_CLIENT_ID="$CLIENT_ID" \
        HELIUM_ADMIN_USERNAME="$ADMIN_USER" HELIUM_ADMIN_PASSWORD="$ADMIN_PASS" \
        ./gradlew setup --console=plain -q ) >"$out" 2>&1
    status=$?
    set -e

    # No match is the normal "client already existed" case, not a failure — hence `|| true`,
    # without which pipefail would abort before the recovery below is even reached.
    NEW_SECRET="$(grep -oE 'DEMO_CLIENT_SECRET=[A-Za-z0-9._~+/-]+' "$out" | head -1 | cut -d= -f2 || true)"

    if [ -n "$NEW_SECRET" ]; then
        rm -f "$out"
        return 0
    fi

    # No secret in the output. An "already exists" abort is expected and recoverable; anything
    # else is a real failure and the build log is the only useful thing we have.
    if grep -q "already exists" "$out"; then
        rm -f "$out"
        return 0
    fi

    if grep -q "rate_limited" "$out"; then
        rm -f "$out"
        die "HeliumID is rate-limiting sign-ins — 5 per account per 10 minutes.
       Wait a few minutes and try again. Once .demo-secret is cached, re-runs need no sign-in at all."
    fi

    cat "$out" >&2
    rm -f "$out"
    die "'./gradlew setup' failed (exit $status). Output above."
}

store_secret() {
    printf '%s' "$1" >"$SECRET_FILE"
    chmod 600 "$SECRET_FILE" 2>/dev/null || true
}

resolve_secret() {
    step "OAuth client '$CLIENT_ID'"

    if [ "$RESET" -eq 1 ]; then
        info "--reset: deleting the existing client"
        delete_client
        rm -f "$SECRET_FILE"
    fi

    # An explicitly exported secret is an instruction, not a hint: use it, and say so plainly if
    # it does not work rather than quietly rotating a credential the caller chose.
    if [ -n "${DEMO_CLIENT_SECRET:-}" ]; then
        if secret_works "$DEMO_CLIENT_SECRET"; then
            ok "using DEMO_CLIENT_SECRET from the environment"
            SECRET="$DEMO_CLIENT_SECRET"
            return
        fi
        die "the exported DEMO_CLIENT_SECRET is not valid for '$CLIENT_ID'.
       Unset it to let this script mint or rotate one, or pass --reset."
    fi

    if [ -f "$SECRET_FILE" ]; then
        local cached; cached="$(cat "$SECRET_FILE")"
        if secret_works "$cached"; then
            ok "cached secret still valid ($(basename "$SECRET_FILE"))"
            SECRET="$cached"
            return
        fi
        warn "the cached secret no longer works — re-registering"
        rm -f "$SECRET_FILE"
    fi

    case "$(client_state)" in
        redirect-mismatch)
            die "'$CLIENT_ID' is registered, but $BASE_URL/callback is not one of its redirect URIs.
       Redirect URIs are matched exactly. Re-register the client with --reset, or point
       DEMO_BASE_URL back at the address it was registered with." ;;
        present)
            # The client outlived its secret — a cleared cache, or a secret rotated elsewhere.
            # Rotating is the only way back in: HeliumID will not read an existing one back out.
            info "client already registered — rotating its secret"
            rotate_secret ;;
        *)
            info "registering scopes and client"
            run_gradle_setup
            # Empty means registration hit a conflict the probe did not predict. Rare, but the
            # recovery is the same one.
            [ -n "$NEW_SECRET" ] || rotate_secret ;;
    esac

    secret_works "$NEW_SECRET" || die "the new secret for '$CLIENT_ID' does not authenticate. Try --reset."

    store_secret "$NEW_SECRET"
    ok "secret stored in $(basename "$SECRET_FILE")"
    SECRET="$NEW_SECRET"
}

# --- 4. run -------------------------------------------------------------------------------

ensure_port_free() {
    # No `-f`: any answer at all means something holds the socket, and an occupant that replies
    # 404 would otherwise slip through and resurface as an opaque Netty BindException.
    if curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then
        die "something is already listening on port $PORT.
       Stop it, or start this one elsewhere:  DEMO_PORT=8082 DEMO_BASE_URL=http://localhost:8082 $0
       A different port needs its redirect URI registered too, so add --reset when you change it."
    fi
}

main() {
    ensure_stack
    ensure_sdk
    resolve_secret

    if [ "$SETUP_ONLY" -eq 1 ]; then
        printf '\n%sSetup complete.%s Start it with:\n\n    %s\n\n' "$BOLD" "$OFF" "$0"
        exit 0
    fi

    ensure_port_free

    printf '\n%sStarting the demo at %s%s\n' "$BOLD" "$BASE_URL" "$OFF"
    info "sign in as $ADMIN_USER / $ADMIN_PASS · Ctrl-C to stop"
    printf '\n'

    # `exec` replaces this shell, so the EXIT trap will never fire. Drop the session by hand.
    cleanup

    cd "$APP_DIR"
    export HELIUM_ISSUER="$ISSUER" DEMO_BASE_URL="$BASE_URL" DEMO_PORT="$PORT"
    export DEMO_CLIENT_ID="$CLIENT_ID" DEMO_CLIENT_SECRET="$SECRET"
    exec ./gradlew run --console=plain
}

main
