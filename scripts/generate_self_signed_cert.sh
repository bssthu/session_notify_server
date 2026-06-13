#!/usr/bin/env sh
set -eu

DNS_NAME="${1:-localhost}"
OUT_DIR="${2:-runtime/secrets}"
mkdir -p "$OUT_DIR"

openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout "$OUT_DIR/server.key" \
  -out "$OUT_DIR/server.crt" \
  -subj "/CN=$DNS_NAME" \
  -addext "subjectAltName=DNS:$DNS_NAME,IP:127.0.0.1"

openssl x509 -in "$OUT_DIR/server.crt" -noout -fingerprint -sha256
echo "Configure this SHA-256 fingerprint in Windows and Android clients."
