#!/usr/bin/env python3
"""Send test notifications to a session_notify server.

This is the "test interface" for triggering notifications from your local
machine so you can check how the Android (or Windows) floating island renders.
It pairs a test device with an explicit code, caches its token, and creates notifications.

Run it from the server project (so ``uv`` can resolve the environment):

    uv run python scripts/send_test_notification.py --pair-code CODE # first run
    uv run python scripts/send_test_notification.py --all            # one of each level
    uv run python scripts/send_test_notification.py --level success
    uv run python scripts/send_test_notification.py --meeting        # countdown
    uv run python scripts/send_test_notification.py --stack 3        # stacked queue
    uv run python scripts/send_test_notification.py --clear          # ack everything

Options:

    --base-url URL      Server base URL (default https://127.0.0.1:8765;
                        use https://10.0.2.2:8765 when talking to a host
                        server from inside the Android emulator).
    --level LEVEL       info | success | important | critical
    --all               Send one notification per level.
    --meeting [SECONDS] Send a meeting-countdown notification (default 300s).
    --stack N           Send N notifications so the island shows the stack state.
    --clear             Acknowledge every active notification.
    --pair-code CODE    Pair a new test device using a code from a bound client
                        (or scripts/issue_bootstrap_code.py for the first device).
    --no-cache          Ignore the cached token; requires --pair-code.

The token cache lives at ``runtime/.test_device.json`` and is keyed by base URL,
so the same test device is reused across runs. After expiry or a server reset,
provide a fresh pairing code; HTTP 401 never creates an anonymous device.

TLS: the server uses a self-signed certificate. For a localhost test trigger
this script skips certificate verification only for loopback. Remote servers
require HTTPS and a trusted certificate. Redirects are not followed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from datetime import datetime
from pathlib import Path
from typing import TextIO

CACHE_PATH = Path("runtime/.test_device.json")
DEFAULT_BASE_URL = "https://127.0.0.1:8765"

# Level -> sample payload. Text mirrors the UI HTML prototype so the rendered
# island matches the design reference.
LEVEL_SAMPLES: dict[str, dict] = {
    "info": {
        "source": "claude",
        "title": "claude completed",
        "body": "Refactor finished. Review the generated diff.",
    },
    "success": {
        "source": "claude",
        "title": "tests passed",
        "body": "All 128 tests passed in 4.2s.",
    },
    "important": {
        "source": "codex",
        "title": "codex idle",
        "body": "Waiting for the next instruction.",
    },
    "critical": {
        "source": "codex",
        "title": "codex needs confirmation",
        "body": "Allow running `npm test` in the current workspace?",
    },
}


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log(message: str = "", *, file: TextIO = sys.stdout) -> None:
    print(f"[{_timestamp()}] {message}", file=file)


def _ssl_context(base_url: str) -> ssl.SSLContext:
    parsed = urlsplit(base_url)
    try:
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))):
        raise ValueError("Use HTTPS for remote servers and a URL without credentials, query or fragment")
    return ssl._create_unverified_context() if loopback else ssl.create_default_context()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(base_url: str, method: str, path: str, payload: dict | None, token: str | None) -> dict:
    url = base_url.rstrip("/") + path
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=_ssl_context(base_url)), NoRedirect(),
        )
        with opener.open(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code, exc.read().decode("utf-8", "replace")) from None


class HttpError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


def _load_cache(base_url: str) -> dict | None:
    if not CACHE_PATH.exists():
        return None
    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        return data.get(base_url)
    except (OSError, json.JSONDecodeError):
        return None


def _save_cache(base_url: str, token: str) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if CACHE_PATH.exists():
        try:
            data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    data[base_url] = token
    CACHE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _bind_device(base_url: str, pair_code: str) -> str:
    if not pair_code:
        raise ValueError("A --pair-code is required to create the test device")
    resp = _request(
        base_url,
        "POST",
        "/api/v1/devices/pair/consume",
        {"name": "test-sender", "platform": "windows", "code": pair_code.strip().upper()},
        token=None,
    )
    token = resp["access_token"]
    _save_cache(base_url, token)
    _log(f"[bind] test device bound, token cached at {CACHE_PATH}")
    return token


def _get_token(args: argparse.Namespace) -> str:
    if args.pair_code:
        return _bind_device(args.base_url, args.pair_code)
    if not args.no_cache:
        cached = _load_cache(args.base_url)
        if cached:
            return cached
    raise ValueError("No cached credential; supply --pair-code from a bound device or the local bootstrap command")


def _create(base_url: str, token: str, notification: dict) -> dict:
    try:
        return _request(base_url, "POST", "/api/v1/notifications", notification, token)
    except HttpError as exc:
        if exc.status != 401:
            raise
        raise ValueError("Test device credential is no longer valid; supply a fresh --pair-code") from exc


def _ack_all(base_url: str, token: str) -> int:
    resp = _request(base_url, "GET", "/api/v1/notifications?status=active", None, token)
    active = resp if isinstance(resp, list) else resp.get("notifications", [])
    count = 0
    for item in active:
        nid = item["id"]
        _request(base_url, "POST", f"/api/v1/notifications/{nid}/ack", {"reason": "test_clear"}, token)
        count += 1
    return count


def _make_notification(level: str, sample: dict, seq: int) -> dict:
    return {
        "source": sample["source"],
        "session_id": f"test-{level}-{seq}",
        "title": sample["title"],
        "body": sample["body"],
        "level": level,
        "requires_ack": True,
        "metadata": {},
    }


def _make_meeting(seconds: int) -> dict:
    return {
        "source": "calendar",
        "session_id": "test-meeting",
        "title": "Design review",
        "body": "Local countdown with reminder pulses",
        "level": "important",
        "requires_ack": False,
        "metadata": {"kind": "meeting", "total_seconds": seconds},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send test notifications to session_notify.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--level", choices=list(LEVEL_SAMPLES), default="critical")
    parser.add_argument("--all", action="store_true", help="send one notification per level")
    parser.add_argument("--meeting", nargs="?", const=300, type=int, default=None,
                        help="send a meeting-countdown notification (default 300s)")
    parser.add_argument("--stack", type=int, default=0, help="send N stacked notifications")
    parser.add_argument("--clear", action="store_true", help="acknowledge all active notifications")
    parser.add_argument("--no-cache", action="store_true", help="bind a fresh test device")
    parser.add_argument("--pair-code", default="", help="pair a new test device with this one-time code")
    args = parser.parse_args(argv)

    token = _get_token(args)

    if args.clear:
        count = _ack_all(args.base_url, token)
        _log(f"[clear] acknowledged {count} active notification(s).")
        return 0

    sent = 0
    seq = int(time.time())

    if args.meeting is not None:
        notif = _make_meeting(args.meeting)
        created = _create(args.base_url, token, notif)
        _log(f"[meeting] {created['level']:9s} | {created['title']} ({args.meeting}s)")
        sent += 1

    if args.stack:
        for i in range(args.stack):
            level = "critical" if i == 0 else ("important" if i % 2 else "info")
            sample = LEVEL_SAMPLES[level]
            notif = _make_notification(level, sample, seq + i)
            notif["title"] = f"{sample['title']} #{i + 1}"
            created = _create(args.base_url, token, notif)
            _log(f"[stack {i + 1}/{args.stack}] {created['level']:9s} | {created['title']}")
            sent += 1

    levels = list(LEVEL_SAMPLES) if args.all else [args.level]
    for level in levels:
        # Skip the level already covered by a single --level default when --all
        # is not set; with --all we emit every level exactly once.
        notif = _make_notification(level, LEVEL_SAMPLES[level], seq + sent)
        created = _create(args.base_url, token, notif)
        _log(f"[notify] {created['level']:9s} | {created['title']}")
        _log(f"         {created['body']}")
        sent += 1

    _log()
    _log(f"Sent {sent} notification(s) to {args.base_url}")
    _log("On Android: open the app or run the e2e script to sync and show the floating island.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HttpError, ValueError) as exc:
        _log(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except urllib.error.URLError as exc:
        _log(f"error: cannot reach {DEFAULT_BASE_URL if '--base-url' not in sys.argv else ''} "
             f"server: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
