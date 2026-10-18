"""Public certificate metadata for authenticated administrators only."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from .security import sha256_fingerprint


def backend_certificate() -> dict | None:
    path = Path(os.getenv("SESSION_NOTIFY_CERT_FILE", "runtime/secrets/server.crt"))
    try:
        # CPython's certificate-file decoder uses OpenSSL and reads no private key.
        details = ssl._ssl._test_decode_cert(str(path))
        der = ssl.PEM_cert_to_DER_cert(path.read_text(encoding="ascii"))
        deadline = datetime.fromtimestamp(ssl.cert_time_to_seconds(details["notAfter"]), timezone.utc)
        return {"id": "backend", "endpoint": "backend", "fingerprint": sha256_fingerprint(der),
                "not_after": deadline.isoformat(), "observed_at": datetime.now(timezone.utc).isoformat()}
    except (OSError, ValueError, KeyError, UnicodeError):
        return None


def certificate_status(backend: dict | None) -> dict:
    result = {"server_time": datetime.now(timezone.utc).isoformat(),
              "certificates": [backend] if backend else [], "gateway_state": "disabled"}
    url = os.getenv("SESSION_NOTIFY_GATEWAY_STATUS_URL", "")
    if not url:
        return result
    result["gateway_state"] = "unavailable"
    try:
        # Operator-configured internal URL only; no client-supplied URL, proxy,
        # credentials or certificate state directories are needed by the backend.
        with build_opener(ProxyHandler({})).open(Request(url), timeout=3) as response:
            payload = json.loads(response.read(16385))
        certificate = payload["certificate"]
        deadline = datetime.fromisoformat(certificate["not_after"])
        observed = datetime.fromisoformat(certificate["observed_at"])
        if deadline.tzinfo is None or observed.tzinfo is None or certificate["id"] != "public-https":
            raise ValueError("Invalid gateway metadata")
        fingerprint = certificate["fingerprint"]
        if len(fingerprint) != 64 or any(c not in "0123456789ABCDEFabcdef" for c in fingerprint):
            raise ValueError("Invalid certificate fingerprint")
        result["certificates"].append({key: certificate[key] for key in
                                       ("id", "endpoint", "fingerprint", "not_after", "observed_at")})
        result["gateway_state"] = "available"
    except (OSError, URLError, ValueError, KeyError, TypeError):
        pass
    return result
