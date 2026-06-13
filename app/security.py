from __future__ import annotations

import hashlib
import re
import secrets


FINGERPRINT_RE = re.compile(r"[^0-9a-fA-F]")


def new_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def normalize_fingerprint(value: str) -> str:
    normalized = FINGERPRINT_RE.sub("", value).upper()
    if len(normalized) != 64:
        raise ValueError("SHA-256 fingerprint must contain 64 hex characters")
    int(normalized, 16)
    return normalized


def fingerprint_matches(data: bytes, expected: str) -> bool:
    return sha256_fingerprint(data) == normalize_fingerprint(expected)
