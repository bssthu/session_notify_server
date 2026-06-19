#!/usr/bin/env sh
set -eu

HOST_ADDRESS="${HOST_ADDRESS:-127.0.0.1}"
PORT="${PORT:-8765}"
CERT_FILE="${CERT_FILE:-runtime/secrets/server.crt}"
KEY_FILE="${KEY_FILE:-runtime/secrets/server.key}"

log_error() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  log_error "Missing certificate files. Run scripts/generate_self_signed_cert.sh first."
  exit 1
fi

uv run uvicorn app.main:app \
  --host "$HOST_ADDRESS" \
  --port "$PORT" \
  --ssl-certfile "$CERT_FILE" \
  --ssl-keyfile "$KEY_FILE" \
  --log-config logging.json
