"""Nginx lifecycle, persistent ACME backoff and local certificate observation.

Never publishes notifications. The internal status port exposes public certificate
metadata only; the application authorizes administrator access to that metadata.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

from certbot_runner import read_json, write_json

WORK = Path("/var/lib/letsencrypt")
LIVE = Path("/etc/letsencrypt/live/session-notify-public")
STATE = WORK / "gateway-state.json"
BACKOFF = WORK / "gateway-ca-backoff.json"
INTERVAL = 6 * 3600
PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
PUBLIC_IP = os.environ.get("HTTPS_PUBLIC_IP", "")
PUBLIC_PORT = os.environ.get("HTTPS_PUBLIC_PORT", "443")


def log(message: str) -> None:
    print(f"[https-gateway] {message}", flush=True)


def log_failure(message: str, error: Exception) -> None:
    detail = str(error)
    if isinstance(error, subprocess.CalledProcessError) and error.stderr:
        # Only the public-certificate OpenSSL validation captures stderr here.
        detail += ": " + error.stderr.decode(errors="replace")[-2000:]
    log(f"{message} ({type(error).__name__}): {detail}")


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


@contextlib.contextmanager
def operation_lock():
    import fcntl
    WORK.mkdir(parents=True, exist_ok=True)
    with (WORK / "gateway.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def remaining_delay(state: dict, backoff: dict, now: float, manual: bool = False) -> float:
    # Manual attempts may skip the regular six-hour check, never a CA embargo.
    deadline = max(float(backoff.get("not_before", 0)), 0 if manual else float(state.get("next_attempt", 0)))
    return max(0, deadline - now)


def schedule_result(state: dict, success: bool, now: float, backoff: dict) -> dict:
    failures = 0 if success else int(state.get("failures", 0)) + 1
    delay = INTERVAL if success else min(INTERVAL, 900 * 2 ** min(failures - 1, 5))
    return {"last_attempt": now, "last_success": now if success else state.get("last_success"),
            "failures": failures, "next_attempt": max(now + delay, float(backoff.get("not_before", 0)))}


def observed_certificate() -> dict:
    from cryptography import x509
    # Diagnostic observation only. This connection sends no HTTP or credentials,
    # and must retain expired certificates so administrators can see the warning.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=PUBLIC_IP) as tls:
            der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    return {"id": "public-https", "endpoint": f"https://{PUBLIC_IP}:{PUBLIC_PORT}",
            "fingerprint": hashlib.sha256(der).hexdigest().upper(),
            "not_after": cert.not_valid_after_utc.isoformat(), "observed_at": iso(time.time())}


def reconcile() -> None:
    """Recover a pending reload even when the CA is unavailable or rate limited."""
    if not (LIVE / "cert.pem").exists():
        return
    subprocess.run(["openssl", "verify", "-CAfile", "/etc/ssl/certs/ca-certificates.crt",
                    "-untrusted", str(LIVE / "chain.pem"), "-purpose", "sslserver", "-verify_ip", PUBLIC_IP,
                    str(LIVE / "cert.pem")], check=True, capture_output=True, timeout=15)
    der = ssl.PEM_cert_to_DER_cert((LIVE / "cert.pem").read_text())
    wanted = hashlib.sha256(der).hexdigest().upper()
    try:
        loaded = observed_certificate()["fingerprint"]
    except (OSError, ValueError):
        loaded = None
    if loaded != wanted:
        # Bootstrap has no TLS listener; activation is still an explicit operation.
        if "ssl_certificate " not in Path("/etc/nginx/conf.d/default.conf").read_text():
            return
        subprocess.run(["nginx", "-t"], check=True, timeout=15)
        subprocess.run(["nginx", "-s", "reload"], check=True, timeout=15)
        for _ in range(10):
            try:
                if observed_certificate()["fingerprint"] == wanted:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Nginx did not load the renewed certificate")
    context = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=PUBLIC_IP) as tls:
            tls.sendall(f"GET /health HTTP/1.1\r\nHost: {PUBLIC_IP}\r\nConnection: close\r\n\r\n".encode())
            response = tls.recv(4096)
            if not response.startswith(b"HTTP/1.1 200 "):
                raise RuntimeError("Gateway /health did not return HTTP 200")
    log("Loaded certificate fingerprint, public trust, IP identity and /health verified")


def run_certbot(arguments: list[str], backoff: Path = BACKOFF) -> bool:
    deadline = float(read_json(backoff).get("not_before", 0))
    if deadline > time.time():
        log(f"CA retry deferred until {iso(deadline)}")
        return False
    env = {**os.environ, "GATEWAY_CA_BACKOFF_FILE": str(backoff)}
    # Inherited stdout/stderr is Docker's bounded log. Certbot's debug log remains
    # in its private state directory; never include it in the status response.
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("certbot_runner.py")), *arguments],
                            env=env, timeout=1800)
    return result.returncode == 0


def renew_once(manual: bool = False) -> bool:
    with operation_lock():
        reconciled = True
        # A valid successor on disk should be usable without another CA request.
        try:
            reconcile()
        except Exception as error:
            log_failure("Certificate/load verification failed; renewal remains eligible", error)
            reconciled = False
        if not (LIVE / "cert.pem").exists():
            return True
        state, backoff = read_json(STATE), read_json(BACKOFF)
        delay = remaining_delay(state, backoff, time.time(), manual)
        if delay > 0:
            if manual:
                log(f"CA retry deferred until {iso(time.time() + delay)}")
            return reconciled
        try:
            success = run_certbot(["renew", "--non-interactive", "--cert-name", "session-notify-public",
                                   "--server", PRODUCTION, "--no-random-sleep-on-renew"])
        except (OSError, subprocess.TimeoutExpired) as error:
            log_failure("Renewal failed", error)
            success = False
        # Always reconcile, including Certbot failure and skipped CA attempts.
        try:
            reconcile()
        except Exception as error:
            log_failure("Post-renewal verification failed", error)
            success = False
        next_state = schedule_result(state, success, time.time(), read_json(BACKOFF))
        write_json(STATE, next_state)
        log(f"Renewal {'succeeded' if success else 'failed'}; next CA check no earlier than {iso(next_state['next_attempt'])}")
        return success


class StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/status":
            self.send_error(404)
            return
        try:
            payload = {"certificate": observed_certificate(), "renewal": read_json(STATE)}
            code = 200
        except Exception:
            payload, code = {"certificate": None, "state": "unavailable"}, 503
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def prepare_state() -> None:
    # Explicit identity, independent of the invoking SSH user's effective group.
    if os.getuid() != 0 or os.getgid() != 0:
        raise RuntimeError("HTTPS gateway must run as configured UID:GID 0:0")
    WORK.mkdir(parents=True, exist_ok=True)
    with operation_lock():
        # Fail before contacting the CA if mounted state is not writable.
        for directory in (WORK, Path("/etc/letsencrypt"), Path("/var/log/letsencrypt"), Path("/var/www/acme")):
            directory.mkdir(parents=True, exist_ok=True)
            # PID 1 repeats across container restarts. A named PID-based probe
            # could be left behind by a crash and block every subsequent start.
            with tempfile.TemporaryFile(dir=directory) as probe:
                probe.write(b"gateway-permission-check")
                probe.flush()
                os.fsync(probe.fileno())


def serve() -> int:
    prepare_state()
    status_server = ThreadingHTTPServer(("0.0.0.0", 9080), StatusHandler)
    status_server.daemon_threads = True
    threading.Thread(target=status_server.serve_forever, daemon=True).start()
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_args: stopping.set())
    children = []
    try:
        children.append(subprocess.Popen(["nginx", "-g", "daemon off;"], start_new_session=True))
        children.append(subprocess.Popen([sys.executable, __file__, "worker"], start_new_session=True))
        while not stopping.wait(1):
            if any(child.poll() is not None for child in children):
                log("Gateway child exited; stopping the deployment unit for container restart")
                return 1
        return 0
    finally:
        status_server.shutdown()
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if command == "serve":
        return serve()
    if command == "worker":
        time.sleep(3)  # Let Nginx open listeners before the first observation.
        while True:
            try:
                renew_once()
            except Exception as error:
                log_failure("Renewal loop failed; will recheck locally in 60 seconds", error)
            time.sleep(60)
    if command == "renew":
        return 0 if renew_once(manual=True) else 1
    if command == "certbot":
        with operation_lock():
            arguments = sys.argv[2:]
            server = arguments[arguments.index("--server") + 1] if "--server" in arguments else PRODUCTION
            staging = server == "https://acme-staging-v02.api.letsencrypt.org/directory"
            return 0 if run_certbot(arguments, WORK / "gateway-staging-backoff.json" if staging else BACKOFF) else 1
    raise ValueError("Expected serve, worker, renew or certbot")


if __name__ == "__main__":
    sys.exit(main())
