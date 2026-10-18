"""Run Certbot and persist CA backoff before Certbot handles an HTTP error.

Only error responses count: Retry-After on normal ACME order polling must not
defer future renewals. No request headers, account data or response bodies are
copied to the backoff file or application logs.
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

CA_HOSTS = {"acme-v02.api.letsencrypt.org", "acme-staging-v02.api.letsencrypt.org"}


class BackoffActive(RuntimeError):
    pass


def read_json(path: Path) -> dict:
    try:
        result = json.loads(path.read_text())
        if not isinstance(result, dict):
            raise ValueError("Invalid persisted gateway state")
        if "not_before" in result and (not isinstance(result["not_before"], (int, float))
                                      or not math.isfinite(result["not_before"]) or result["not_before"] < 0):
            raise ValueError("Invalid persisted CA deadline")
        return result
    except FileNotFoundError:
        return {}


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    with temporary.open("w") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def retry_deadline(status: int, headers: dict, body: dict, now: float) -> float | None:
    if status < 400:
        return None
    normalized = {key.lower(): str(value) for key, value in headers.items()}
    candidates = []
    value = normalized.get("retry-after", "").strip()
    if value.isdigit():
        candidates.append(now + int(value))
    elif value:
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is not None:
                candidates.append(date.timestamp())
        except (ValueError, TypeError, OverflowError):
            pass
    problems = [body] if isinstance(body, dict) else []
    if isinstance(body, dict) and isinstance(body.get("subproblems"), list):
        problems.extend(body["subproblems"])
    for problem in problems:
        if not isinstance(problem, dict):
            continue
        for date in re.findall(r"retry after (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC", str(problem.get("detail", "")), re.I):
            try:
                candidates.append(datetime.strptime(date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
            except ValueError:
                pass
    limited = status == 429 or any(str(p.get("type", "")).endswith(":rateLimited") for p in problems if isinstance(p, dict))
    valid = [value for value in candidates if math.isfinite(value) and value >= now]
    if valid:
        return max(valid) + 5  # Avoid retrying on the boundary of a CA clock tick.
    return now + 6 * 3600 if limited else None


def record_response(path: Path, url: str, status: int, headers: dict, body: dict, now: float) -> None:
    if urlsplit(url).hostname not in CA_HOSTS:
        return
    deadline = retry_deadline(status, headers, body, now)
    if deadline is not None:
        previous = read_json(path)
        write_json(path, {"not_before": max(float(previous.get("not_before", 0)), deadline)})


def main() -> int:
    import requests
    from certbot.main import main as certbot_main

    path = Path(os.environ["GATEWAY_CA_BACKOFF_FILE"])
    original = requests.sessions.Session.send

    def send(session, request, **kwargs):
        is_ca = urlsplit(request.url).hostname in CA_HOSTS
        if is_ca:
            deadline = read_json(path).get("not_before", 0)
            if deadline > time.time():
                # Certbot may fall back from a failed ARI request to new-order in
                # the same invocation. That fallback must also respect the CA.
                raise BackoffActive(f"CA retry deferred until {datetime.fromtimestamp(deadline, timezone.utc).isoformat()}")
        response = original(session, request, **kwargs)
        if is_ca and response.status_code >= 400:
            try:
                body = response.json()
            except ValueError:
                body = {}
            record_response(path, response.url, response.status_code, dict(response.headers), body, time.time())
        return response

    requests.sessions.Session.send = send
    return certbot_main(sys.argv[1:]) or 0


if __name__ == "__main__":
    sys.exit(main())
