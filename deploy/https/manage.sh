#!/usr/bin/env bash
# Operator-run only. Never starts/recreates/stops the original `server` service.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
STATE="$ROOT/runtime/public-https"
CERT_NAME=session-notify-public
LIVE="$STATE/acme/live/$CERT_NAME"
PRODUCTION=https://acme-v02.api.letsencrypt.org/directory
STAGING=https://acme-staging-v02.api.letsencrypt.org/directory
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[public-https] %s\n' "$*"; }
[[ $(uname -s) == Linux ]] || fail 'Run on the Linux Docker host.'
[[ -f "$STATE/config.env" ]] || fail 'Create runtime/public-https/config.env from deploy/https/env.example first.'
# This is a trusted operator-owned shell configuration, never a downloaded input.
# shellcheck source=/dev/null
source "$STATE/config.env"
: "${HTTPS_PUBLIC_IP:?}" "${HTTPS_COMPOSE_PROJECT:?}" "${HTTPS_UPSTREAM_TLS_NAME:?}" "${HTTPS_CA_BUNDLE:?}"
: "${HTTPS_PUBLIC_PORT:=443}" "${HTTPS_ACME_EMAIL=}" "${HTTPS_ACME_REGISTER_WITHOUT_EMAIL:=false}"
[[ $HTTPS_PUBLIC_PORT =~ ^[0-9]{1,5}$ ]] || fail 'HTTPS_PUBLIC_PORT must be an integer from 1 to 65535, excluding ACME port 80.'
HTTPS_PUBLIC_PORT=$((10#$HTTPS_PUBLIC_PORT))
(( HTTPS_PUBLIC_PORT >= 1 && HTTPS_PUBLIC_PORT <= 65535 && HTTPS_PUBLIC_PORT != 80 )) || fail 'HTTPS_PUBLIC_PORT must be an integer from 1 to 65535, excluding ACME port 80.'
[[ $HTTPS_ACME_REGISTER_WITHOUT_EMAIL == true || $HTTPS_ACME_REGISTER_WITHOUT_EMAIL == false ]] || fail 'HTTPS_ACME_REGISTER_WITHOUT_EMAIL must be true or false.'
# Compose interpolation must use this same value, including under sudo/systemd.
export HTTPS_PUBLIC_PORT
# Certbot writes bind-mounted state as the operator, so user timers need no sudo.
HTTPS_ACME_UID=$(id -u)
HTTPS_ACME_GID=$(id -g)
export HTTPS_ACME_UID HTTPS_ACME_GID
PUBLIC_URL="https://$HTTPS_PUBLIC_IP:$HTTPS_PUBLIC_PORT"
[[ $HTTPS_PUBLIC_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'Configure one public IPv4 address for this deployment.'
IFS=. read -r -a octets <<< "$HTTPS_PUBLIC_IP"
for octet in "${octets[@]}"; do (( 10#$octet <= 255 )) || fail 'Invalid IPv4 address.'; done
[[ $HTTPS_UPSTREAM_TLS_NAME =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || fail 'Use an exact, non-wildcard DNS SAN for HTTPS_UPSTREAM_TLS_NAME.'
[[ $HTTPS_COMPOSE_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'Set the EXISTING Compose project name.'
for executable in docker openssl curl flock timeout ss python3; do
    command -v "$executable" >/dev/null || fail "Missing prerequisite: $executable"
done
[[ -r "$HTTPS_CA_BUNDLE" ]] || fail 'Public system CA bundle is missing.'
mkdir -p "$STATE"/{nginx,webroot,upstream,acme/live,acme/archive,work,logs}
chmod 700 "$STATE"
chmod 755 "$STATE/nginx" "$STATE/webroot" "$STATE/upstream"
exec 9>"$STATE/operator.lock"
flock -n 9 || fail 'Another HTTPS operation is running; retry after it finishes.'
TMP=$(mktemp -d "$STATE/check.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT

dc() { docker compose --project-name "$HTTPS_COMPOSE_PROJECT" -f compose.yaml -f compose.https.yaml "$@"; }
backend_ports=$(dc config --format json | python3 deploy/compose_ports.py)
read -r HTTPS_UPSTREAM_PORT HTTPS_UPSTREAM_HOST_PORT <<< "$backend_ports"
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256; }
require_server() {
    [[ -n $(dc ps --status running -q server) ]] || fail 'No running server in this project. Check project name; do not create a new server/database.'
}
preflight() {
    require_server
    local original="$ROOT/runtime/secrets/server.crt"
    [[ -r $original ]] || fail 'Original public certificate not found; do not regenerate it.'
    openssl x509 -in "$original" -noout -ext subjectAltName > "$TMP/san"
    tr ',' '\n' < "$TMP/san" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
        grep -Fxiq "DNS:$HTTPS_UPSTREAM_TLS_NAME" || fail 'Configured name is not an exact DNS SAN. IP-only SAN is unsupported by this Nginx path; stop, do not disable verification.'
    openssl verify -CAfile "$original" -purpose sslserver \
        -verify_hostname "$HTTPS_UPSTREAM_TLS_NAME" "$original" >/dev/null
    timeout 15 openssl s_client -connect "127.0.0.1:$HTTPS_UPSTREAM_HOST_PORT" \
        -servername "$HTTPS_UPSTREAM_TLS_NAME" -verify_hostname "$HTTPS_UPSTREAM_TLS_NAME" \
        -CAfile "$original" -verify_return_error -showcerts \
        </dev/null > "$TMP/upstream.pem" 2> "$TMP/upstream.log" || {
            cat "$TMP/upstream.log" >&2; fail 'Original HTTPS upstream validation failed.';
        }
    [[ $(fp "$original") == "$(fp "$TMP/upstream.pem")" ]] || fail 'Running upstream certificate differs from the original file.'
    if [[ -e "$STATE/upstream/server.crt" ]]; then
        [[ $(fp "$STATE/upstream/server.crt") == "$(fp "$original")" ]] || fail 'Pinned upstream certificate changed; review rotation explicitly.'
    else
        # Only the PUBLIC certificate is copied. The original private key stays put.
        install -m 644 "$original" "$STATE/upstream/server.crt"
    fi
    log 'Original upstream certificate, DNS SAN, live fingerprint and project verified.'
}
validate_public() {
    [[ -f "$LIVE/cert.pem" && -f "$LIVE/chain.pem" ]] || fail 'No production certificate yet; run issuance first.'
    # System trust + IP identity rejects staging, self-signed, expired or wrong-IP certificates.
    openssl verify -CAfile "$HTTPS_CA_BUNDLE" -untrusted "$LIVE/chain.pem" \
        -purpose sslserver -verify_ip "$HTTPS_PUBLIC_IP" "$LIVE/cert.pem" >/dev/null
    local issuer
    issuer=$(openssl x509 -in "$LIVE/cert.pem" -noout -issuer)
    [[ ${issuer^^} != *STAGING* && ${issuer^^} != *PRETEND* ]] || fail 'Refusing a staging certificate.'
}
loaded_fp() {
    timeout 15 openssl s_client -connect "127.0.0.1:$HTTPS_PUBLIC_PORT" -servername "$HTTPS_PUBLIC_IP" \
        -verify_ip "$HTTPS_PUBLIC_IP" -CAfile "$HTTPS_CA_BUNDLE" \
        -verify_return_error -showcerts </dev/null > "$TMP/frontend.pem" 2> "$TMP/frontend.log" || return 1
    fp "$TMP/frontend.pem"
}
verify_frontend() {
    validate_public
    local want got
    want=$(fp "$LIVE/cert.pem")
    got=$(loaded_fp) || { cat "$TMP/frontend.log" >&2; fail "Local HTTPS port $HTTPS_PUBLIC_PORT TLS validation failed."; }
    [[ $want == "$got" ]] || fail "HTTPS port $HTTPS_PUBLIC_PORT is still serving a different certificate; reload did not take effect."
    curl --noproxy '*' --fail --silent --show-error --max-time 20 \
        --cacert "$HTTPS_CA_BUNDLE" --connect-to "$HTTPS_PUBLIC_IP:$HTTPS_PUBLIC_PORT:127.0.0.1:$HTTPS_PUBLIC_PORT" \
        "$PUBLIC_URL/health" > "$TMP/health.json"
    openssl x509 -in "$TMP/frontend.pem" -noout -dates -fingerprint -sha256
    openssl x509 -in "$TMP/frontend.pem" -noout -checkend 172800 >/dev/null || fail 'Loaded certificate expires in under 48 hours; investigate renewal now.'
    log "Local HTTPS port $HTTPS_PUBLIC_PORT trust, IP identity, loaded certificate and /health verified. Public endpoint: $PUBLIC_URL . Check Internet reachability separately."
}
activate() {
    validate_public
    [[ -r "$STATE/upstream/server.crt" ]] || fail 'Run preflight first.'
    [[ -f "$STATE/nginx/default.conf" ]] || fail 'Run bootstrap first.'
    cp "$STATE/nginx/default.conf" "$TMP/previous.conf"
    sed -e "s/__PUBLIC_IP__/$HTTPS_PUBLIC_IP/g" \
        -e "s/__UPSTREAM_TLS_NAME__/$HTTPS_UPSTREAM_TLS_NAME/g" \
        -e "s/__UPSTREAM_PORT__/$HTTPS_UPSTREAM_PORT/g" \
        deploy/https/https.conf.template > "$STATE/nginx/default.conf.new"
    chmod 644 "$STATE/nginx/default.conf.new"
    mv "$STATE/nginx/default.conf.new" "$STATE/nginx/default.conf"
    if ! dc exec -T public-https nginx -t; then
        cp "$TMP/previous.conf" "$STATE/nginx/default.conf"
        fail 'Nginx config test failed; previous config restored, no reload requested.'
    fi
    dc exec -T public-https nginx -s reload
    # A successful signal does not prove workers loaded the new leaf certificate.
    local want got attempt
    want=$(fp "$LIVE/cert.pem")
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        got=$(loaded_fp) || got=''
        [[ $got == "$want" ]] && break
        sleep 2
    done
    verify_frontend
}
issue() {
    local mode=$1 consent=${2:-}
    [[ $consent == --accept-le-terms ]] || fail 'Read the linked CA terms in README; then explicitly pass --accept-le-terms.'
    local -a account=()
    if [[ $HTTPS_ACME_REGISTER_WITHOUT_EMAIL == true ]]; then
        [[ -z $HTTPS_ACME_EMAIL ]] || fail 'Leave HTTPS_ACME_EMAIL empty when registering without email.'
        account=(--register-unsafely-without-email)
    else
        [[ $HTTPS_ACME_EMAIL == *@* && $HTTPS_ACME_EMAIL != REPLACE* ]] || fail 'Set your ACME contact email, or explicitly opt into registration without email.'
        account=(--email "$HTTPS_ACME_EMAIL")
    fi
    require_server
    local -a extra=()
    if [[ $mode == test ]]; then
        # A completely separate lineage/account. Nginx cannot mount this tree.
        extra=(--server "$STAGING" --config-dir /etc/letsencrypt/staging/config \
            --work-dir /var/lib/letsencrypt/staging --logs-dir /var/log/letsencrypt/staging)
    else
        extra=(--server "$PRODUCTION")
    fi
    dc run --rm --no-deps public-certbot certonly --non-interactive --agree-tos \
        "${account[@]}" --webroot --webroot-path /var/www/acme \
        --preferred-challenges http --required-profile shortlived \
        --ip-address "$HTTPS_PUBLIC_IP" --cert-name "$CERT_NAME" "${extra[@]}"
    if [[ $mode == test ]]; then
        log 'Staging challenge succeeded; no staging certificate was activated.'
    else
        validate_public
        log 'Production certificate obtained. Next: activate, external verification, then enable renewal timer.'
    fi
}
case "${1:-}" in
    preflight) preflight ;;
    bootstrap)
        preflight
        [[ ! -e "$STATE/nginx/default.conf" ]] || fail 'Config already exists; bootstrap will not overwrite an active front door.'
        ss -H -ltn "( sport = :80 or sport = :$HTTPS_PUBLIC_PORT )" > "$TMP/listeners"
        [[ ! -s "$TMP/listeners" ]] || { cat "$TMP/listeners" >&2; fail "TCP 80 or $HTTPS_PUBLIC_PORT already in use; do not stop the existing service blindly."; }
        install -m 644 deploy/https/bootstrap.conf "$STATE/nginx/default.conf"
        dc config --quiet
        dc up -d --no-deps public-https
        dc exec -T public-https nginx -t
        log "ACME-only port 80 is ready; HTTPS port $HTTPS_PUBLIC_PORT intentionally has no TLS listener yet."
        ;;
    test-issuance) issue test "${2:-}" ;;
    issue) issue production "${2:-}" ;;
    activate) activate ;;
    verify) verify_frontend ;;
    renew)
        [[ -f "$LIVE/cert.pem" ]] || fail 'Complete initial production issuance first.'
        rm -f "$STATE/work/renewed"
        dc run --rm --no-deps public-certbot renew --non-interactive \
            --cert-name "$CERT_NAME" --server "$PRODUCTION" --no-random-sleep-on-renew \
            --deploy-hook 'touch /var/lib/letsencrypt/renewed'
        validate_public
        got=$(loaded_fp) || got=''
        if [[ -f "$STATE/work/renewed" || $got != "$(fp "$LIVE/cert.pem")" ]]; then
            # Also retries a previously successful renewal whose reload failed.
            activate
        else
            verify_frontend
        fi
        ;;
    compose) shift; dc "$@" ;;
    *) fail 'Usage: manage.sh preflight|bootstrap|test-issuance --accept-le-terms|issue --accept-le-terms|activate|verify|renew|compose ...' ;;
esac
