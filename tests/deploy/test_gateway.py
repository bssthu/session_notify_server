"""Offline renewal scheduling/recovery tests. No CA, Docker or real certificates."""
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / "deploy/https/gateway"
sys.path.insert(0, str(DIRECTORY))
import certbot_runner as runner
import gateway
sys.path.remove(str(DIRECTORY))

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc).timestamp()


@pytest.mark.parametrize("headers,body,expected", [
    ({"Retry-After": "3600"}, {}, NOW + 3605),
    ({"retry-after": "Sun, 18 Oct 2026 02:00:00 GMT"}, {}, NOW + 7205),
    ({}, {"type": "urn:ietf:params:acme:error:rateLimited", "detail": "retry after 2026-10-18 03:00:00 UTC"}, NOW + 10805),
    ({"Retry-After": "60"}, {"subproblems": [{"detail": "retry after 2026-10-18 03:00:00 UTC"}]}, NOW + 10805),
    ({"Retry-After": "broken"}, {}, NOW + 21600),
])
def test_ca_deadlines(headers, body, expected):
    assert runner.retry_deadline(429, headers, body, NOW) == expected


def test_normal_acme_polling_does_not_block_renewal_but_503_does():
    assert runner.retry_deadline(202, {"Retry-After": "60"}, {}, NOW) is None
    assert runner.retry_deadline(503, {"Retry-After": "60"}, {}, NOW) == NOW + 65
    assert runner.retry_deadline(400, {}, {}, NOW) is None


def test_http_observer_persists_latest_deadline_without_response_secrets(tmp_path):
    path = tmp_path / "ca.json"
    url = "https://acme-v02.api.letsencrypt.org/acme/new-order"
    runner.record_response(path, url, 429, {"Retry-After": "7200", "Replay-Nonce": "private-nonce"}, {}, NOW)
    runner.record_response(path, url, 429, {"Retry-After": "60"}, {"detail": "private-body"}, NOW)
    assert runner.read_json(path) == {"not_before": NOW + 7205}
    assert "private" not in path.read_text()
    runner.record_response(path, "https://example.test/", 429, {"Retry-After": "86400"}, {}, NOW)
    assert runner.read_json(path)["not_before"] == NOW + 7205


def test_same_certbot_invocation_cannot_fall_back_to_new_order_during_ca_backoff(tmp_path, monkeypatch):
    path = tmp_path / "ca.json"
    calls = []
    class Session:
        def send(self, request, **_kwargs):
            calls.append(request.url)
            return SimpleNamespace(url=request.url, status_code=429, headers={"Retry-After": "7200"}, json=lambda: {})
    def certbot_main(_arguments):
        session = Session()
        session.send(SimpleNamespace(url="https://acme-v02.api.letsencrypt.org/acme/renewal-info/example"))
        with pytest.raises(runner.BackoffActive):
            session.send(SimpleNamespace(url="https://acme-v02.api.letsencrypt.org/acme/new-order"))
        return 1
    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(sessions=SimpleNamespace(Session=Session)))
    monkeypatch.setitem(sys.modules, "certbot.main", SimpleNamespace(main=certbot_main))
    monkeypatch.setenv("GATEWAY_CA_BACKOFF_FILE", str(path))
    monkeypatch.setattr(runner.time, "time", lambda: NOW)
    assert runner.main() == 1
    assert len(calls) == 1
    assert runner.read_json(path)["not_before"] == NOW + 7205


def test_rate_limit_without_header_is_conservative():
    assert runner.retry_deadline(400, {}, {"type": "urn:ietf:params:acme:error:rateLimited"}, NOW) == NOW + 21600
    assert runner.retry_deadline(429, {"Retry-After": "0"}, {}, NOW) == NOW + 5


def test_backoff_survives_restart_and_manual_renew_cannot_bypass_it(tmp_path, monkeypatch):
    path = tmp_path / "backoff.json"
    runner.write_json(path, {"not_before": NOW + 7200})
    monkeypatch.setattr(gateway.time, "time", lambda: NOW)
    monkeypatch.setattr(gateway.subprocess, "run", lambda *_a, **_k: pytest.fail("Must not contact CA during backoff"))
    assert not gateway.run_certbot(["renew"], path)
    assert gateway.remaining_delay({}, runner.read_json(path), NOW, manual=True) == 7200


def test_retry_schedule_is_bounded_and_honors_later_ca_deadline():
    state = gateway.schedule_result({}, False, NOW, {})
    assert state["next_attempt"] == NOW + 900
    state = gateway.schedule_result(state, False, NOW, {"not_before": NOW + 86400})
    assert state["next_attempt"] == NOW + 86400
    assert gateway.schedule_result(state, True, NOW, {})["failures"] == 0
    assert gateway.schedule_result({"failures": 1000}, False, NOW, {})["next_attempt"] == NOW + 21600


@pytest.fixture
def renewal(tmp_path, monkeypatch):
    live = tmp_path / "live"
    live.mkdir()
    (live / "cert.pem").write_text("synthetic")
    monkeypatch.setattr(gateway, "LIVE", live)
    monkeypatch.setattr(gateway, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(gateway, "BACKOFF", tmp_path / "backoff.json")
    monkeypatch.setattr(gateway, "operation_lock", nullcontext)
    monkeypatch.setattr(gateway.time, "time", lambda: NOW)
    return tmp_path


def test_certbot_failure_still_recovers_pending_nginx_reload(renewal, monkeypatch):
    calls = []
    monkeypatch.setattr(gateway, "reconcile", lambda: calls.append("reconcile"))
    monkeypatch.setattr(gateway, "run_certbot", lambda _args: calls.append("certbot") or False)
    assert not gateway.renew_once()
    assert calls == ["reconcile", "certbot", "reconcile"]
    assert runner.read_json(gateway.STATE)["next_attempt"] == NOW + 900


def test_embargo_blocks_ca_but_not_reload_recovery(renewal, monkeypatch):
    calls = []
    runner.write_json(gateway.BACKOFF, {"not_before": NOW + 7200})
    monkeypatch.setattr(gateway, "reconcile", lambda: calls.append("reconcile"))
    monkeypatch.setattr(gateway, "run_certbot", lambda _args: pytest.fail("CA embargo"))
    gateway.renew_once(manual=True)
    assert calls == ["reconcile"]


def test_manual_deferred_renewal_reports_invalid_loaded_certificate(renewal, monkeypatch):
    runner.write_json(gateway.BACKOFF, {"not_before": NOW + 7200})
    def expired():
        raise RuntimeError("expired")
    monkeypatch.setattr(gateway, "reconcile", expired)
    monkeypatch.setattr(gateway, "run_certbot", lambda _args: pytest.fail("CA embargo"))
    assert not gateway.renew_once(manual=True)


def test_certbot_timeout_schedules_backoff_and_does_not_skip_recovery(renewal, monkeypatch):
    calls = []
    def fail(_args):
        raise subprocess.TimeoutExpired("certbot", 1800)
    monkeypatch.setattr(gateway, "run_certbot", fail)
    monkeypatch.setattr(gateway, "reconcile", lambda: calls.append("reconcile"))
    assert not gateway.renew_once()
    assert len(calls) == 2
    assert runner.read_json(gateway.STATE)["failures"] == 1


def test_reloaded_certificate_must_be_verified_before_success(renewal, monkeypatch):
    monkeypatch.setattr(gateway, "run_certbot", lambda _args: True)
    def fail():
        raise RuntimeError("Still serving old certificate")
    monkeypatch.setattr(gateway, "reconcile", fail)
    assert not gateway.renew_once()
    assert runner.read_json(gateway.STATE)["last_success"] is None


def test_fresh_deployment_does_not_issue_or_accept_terms_automatically(renewal, monkeypatch):
    (gateway.LIVE / "cert.pem").unlink()
    monkeypatch.setattr(gateway, "run_certbot", lambda _args: pytest.fail("No automatic initial issuance"))
    assert gateway.renew_once()


def test_corrupt_backoff_fails_closed_instead_of_retrying(renewal, monkeypatch):
    gateway.BACKOFF.write_text("corrupt")
    monkeypatch.setattr(gateway, "reconcile", lambda: None)
    monkeypatch.setattr(gateway, "run_certbot", lambda _args: pytest.fail("Corrupt embargo must not be ignored"))
    with pytest.raises(ValueError):
        gateway.renew_once()


@pytest.mark.parametrize("state", ["[]", '{"not_before": "tomorrow"}', '{"not_before": NaN}'])
def test_invalid_persisted_deadline_never_becomes_an_immediate_retry(tmp_path, state):
    path = tmp_path / "state.json"
    path.write_text(state)
    with pytest.raises(ValueError):
        runner.read_json(path)


def test_gateway_refuses_invoker_dependent_nonroot_identity(monkeypatch):
    monkeypatch.setattr(gateway.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(gateway.os, "getgid", lambda: 111, raising=False)
    with pytest.raises(RuntimeError, match="UID:GID 0:0"):
        gateway.prepare_state()


@pytest.mark.parametrize("failed_child", [0, 1, None])
def test_gateway_supervisor_stops_both_process_groups_on_child_exit_or_shutdown(monkeypatch, failed_child):
    stopped = []
    processes = []
    status = SimpleNamespace(daemon_threads=False, serve_forever=lambda: None, shutdown=lambda: stopped.append("status"))
    monkeypatch.setattr(gateway, "prepare_state", lambda: None)
    monkeypatch.setattr(gateway, "ThreadingHTTPServer", lambda *_args: status)
    monkeypatch.setattr(gateway.threading, "Thread", lambda **_kwargs: SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(gateway.threading, "Event", lambda: SimpleNamespace(wait=lambda _seconds: failed_child is None, set=lambda: None))
    monkeypatch.setattr(gateway.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(gateway.os, "killpg", lambda pid, _sig: stopped.append(pid), raising=False)
    def popen(arguments, **kwargs):
        index = len(processes)
        assert kwargs["start_new_session"] is True
        child = SimpleNamespace(pid=100 + index, poll=lambda: 1 if index == failed_child else None,
                                wait=lambda **_kwargs: 0)
        processes.append(child)
        return child
    monkeypatch.setattr(gateway.subprocess, "Popen", popen)
    assert gateway.serve() == (0 if failed_child is None else 1)
    assert len(processes) == 2
    assert stopped == ["status", 100, 101]
