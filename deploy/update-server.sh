#!/usr/bin/env bash
# Update an existing deployment; paths are relative to this checkout.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[update] %s\n' "$*"; }
pull=true
update_https=false
for argument in "$@"; do
    case "$argument" in
        --no-pull) pull=false ;;
        --https) update_https=true ;;
        --help|-h)
            printf '%s\n' 'Usage: bash deploy/update-server.sh [--no-pull] [--https]' \
                'Default: fast-forward the current branch, rebuild server, verify backend TLS/health.' \
                '--no-pull: rebuild the current clean checkout without fetching (also allows detached HEAD).' \
                '--https: also build/update the HTTPS gateway with its managed renewal process; never perform initial issuance.'
            exit 0 ;;
        *) fail "Unknown argument: $argument" ;;
    esac
done
[[ $(uname -s) == Linux ]] || fail 'Run on the Linux Docker host.'
for executable in git docker curl flock python3; do
    command -v "$executable" >/dev/null || fail "Missing prerequisite: $executable"
done
[[ $(git rev-parse --show-toplevel) == "$ROOT" ]] || fail 'Run from the server Git checkout.'
if [[ -n $(git status --porcelain) ]]; then
    git status --short
    fail 'Working tree is not clean. Keep machine configuration under ignored runtime/.'
fi
if [[ -f runtime/deploy/update.env ]]; then
    # This is a trusted operator-owned configuration, never downloaded input.
    # shellcheck source=/dev/null
    source runtime/deploy/update.env
fi
: "${UPDATE_COMPOSE_PROJECT=}" "${UPDATE_HEALTH_URL=}"
: "${UPDATE_HEALTH_CA_FILE:=runtime/secrets/server.crt}"
: "${UPDATE_HEALTH_RETRIES:=30}" "${UPDATE_HEALTH_INTERVAL_SECONDS:=2}"
[[ -z $UPDATE_HEALTH_URL || $UPDATE_HEALTH_URL == https://* ]] || fail 'UPDATE_HEALTH_URL must use HTTPS.'
[[ -r $UPDATE_HEALTH_CA_FILE ]] || fail 'Backend CA/certificate file is not readable.'
[[ $UPDATE_HEALTH_RETRIES =~ ^[0-9]{1,3}$ && $UPDATE_HEALTH_INTERVAL_SECONDS =~ ^[0-9]{1,2}$ ]] || fail 'Invalid health retry settings.'
UPDATE_HEALTH_RETRIES=$((10#$UPDATE_HEALTH_RETRIES))
UPDATE_HEALTH_INTERVAL_SECONDS=$((10#$UPDATE_HEALTH_INTERVAL_SECONDS))
(( UPDATE_HEALTH_RETRIES >= 1 && UPDATE_HEALTH_RETRIES <= 300 && UPDATE_HEALTH_INTERVAL_SECONDS <= 60 )) || fail 'Health retries must be 1..300 and interval 0..60 seconds.'
compose_options=()
if [[ -n $UPDATE_COMPOSE_PROJECT ]]; then
    [[ $UPDATE_COMPOSE_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'Invalid Compose project name.'
    compose_options=(--project-name "$UPDATE_COMPOSE_PROJECT")
fi
dc() { docker compose "${compose_options[@]}" "$@"; }
https() { bash "$ROOT/deploy/https/manage.sh" "$@"; }
if [[ -z $UPDATE_HEALTH_URL ]]; then
    backend_ports=$(dc config --format json | python3 deploy/compose_ports.py)
    read -r backend_port backend_host_port <<< "$backend_ports"
    UPDATE_HEALTH_URL="https://127.0.0.1:$backend_host_port/health"
fi
docker compose version >/dev/null
mkdir -p runtime/deploy
chmod 700 runtime/deploy
exec 9>runtime/deploy/update.lock
flock -n 9 || fail 'Another application update is running.'
server_id=$(dc ps --all -q server)
[[ -n $server_id ]] || fail 'No existing server container in this Compose project. Check the project name or follow first-deployment instructions.'
if $update_https; then
    [[ -f runtime/public-https/acme/live/session-notify-public/cert.pem ]] || fail 'Complete initial HTTPS issuance and activation first.'
    grep -q 'ssl_certificate ' runtime/public-https/nginx/default.conf || fail 'HTTPS has not been activated.'
    [[ $(https compose ps --all -q server) == "$server_id" ]] || fail 'Backend and HTTPS configurations select different Compose projects.'
    [[ -n $(https compose ps --all -q public-https) ]] || fail 'No existing HTTPS entry point. Complete initial deployment first.'
fi
if $pull; then
    branch=$(git symbolic-ref --quiet --short HEAD) || fail 'Detached HEAD: select a tracking branch, or use --no-pull intentionally.'
    upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}') || fail 'The current branch has no upstream.'
    log "Fast-forwarding $branch from $upstream."
    git pull --ff-only
    # Run the updated script and reload its configuration before applying it.
    # The restarted process rechecks cleanliness and acquires the lock again.
    exec 9>&-
    next_arguments=(--no-pull)
    $update_https && next_arguments+=(--https)
    exec bash "$ROOT/deploy/update-server.sh" "${next_arguments[@]}"
fi
log "Deploying $(git rev-parse --short HEAD)."
dc config --quiet
if $update_https; then
    https compose config --quiet
    https compose build --pull public-https
fi
dc up -d --build server
healthy=false
for ((attempt=1; attempt<=UPDATE_HEALTH_RETRIES; attempt++)); do
    if response=$(curl --noproxy '*' --fail --silent --show-error --max-time 5 \
        --cacert "$UPDATE_HEALTH_CA_FILE" "$UPDATE_HEALTH_URL" 2>/dev/null) &&
        grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' <<< "$response"; then
        healthy=true
        break
    fi
    if (( attempt < UPDATE_HEALTH_RETRIES )); then sleep "$UPDATE_HEALTH_INTERVAL_SECONDS"; fi
done
if ! $healthy; then
    dc ps server || true
    # Do not dump request logs or credentials automatically.
    fail 'Backend TLS/health check failed; inspect local logs. No automatic rollback was attempted.'
fi
if $update_https; then
    https compose up -d --no-deps public-https
    https activate
    log 'HTTPS configuration and local trusted health check passed. Check external reachability separately.'
fi
dc ps server
log 'Update completed. Data volumes and existing device credentials were retained.'
