import io
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from app import certificate_status as module


CERT = {"id": "public-https", "endpoint": "https://203.0.113.10:8443", "fingerprint": "AB" * 32,
        "not_after": "2026-10-18T07:00:00+00:00", "observed_at": "2026-10-18T06:00:00+00:00"}


def test_only_admin_can_read_certificate_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_GATEWAY_STATUS_URL", "")
    client = TestClient(create_app(tmp_path / "certificate-api.db"))
    admin = client.post("/api/v1/devices/bind", json={"name": "admin", "platform": "windows"}).json()
    member = client.post("/api/v1/devices/bind", json={"name": "member", "platform": "android"}).json()
    path = "/api/v1/server/certificates"
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer " + member["access_token"]}).status_code == 403
    response = client.get(path, headers={"Authorization": "Bearer " + admin["access_token"]})
    assert response.status_code == 200
    assert response.json()["gateway_state"] == "disabled"


def test_gateway_response_contains_only_certificate_metadata(monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_GATEWAY_STATUS_URL", "http://public-https:9080/status")
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "http://public-https:9080/status"
            assert timeout == 3
            return io.BytesIO(json.dumps({"certificate": {**CERT, "private": "never-forward"}, "renewal": {"anything": "hidden"}}).encode())
    monkeypatch.setattr(module, "build_opener", lambda _proxy: Opener())
    result = module.certificate_status(None)
    assert result["certificates"] == [CERT]
    assert result["gateway_state"] == "available"
    assert "never-forward" not in json.dumps(result)


def test_unreachable_gateway_preserves_backend_expiry(monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_GATEWAY_STATUS_URL", "http://public-https:9080/status")
    def unavailable(_proxy):
        raise OSError("not deployed")
    monkeypatch.setattr(module, "build_opener", unavailable)
    backend = {**CERT, "id": "backend"}
    result = module.certificate_status(backend)
    assert result["certificates"] == [backend]
    assert result["gateway_state"] == "unavailable"


def test_missing_backend_certificate_is_optional(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_CERT_FILE", str(tmp_path / "missing.crt"))
    assert module.backend_certificate() is None
