from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import create_app
from app.payload_limits import RequestBodyLimitMiddleware, validate_json_budget, validate_metadata
from app.schemas import DevicePlatform, HookPayload, NotificationCreate, utc_now
from app.storage import PublishLimitError, Storage


def test_metadata_contract_preserves_structured_tool_inputs():
    metadata = {"hook_event_name": "PreToolUse", "tool_input": {"questions": [{"title": "Continue?"}]}}
    assert validate_metadata(metadata) == metadata
    with pytest.raises(ValueError, match="scalar"):
        validate_metadata({"hook_event_name": {"previous_format": "Stop"}})
    assert validate_metadata({"local_only": "1", "countdownLocal": "1", "tag": "work"}) == {"tag": "work"}
    with pytest.raises(ValidationError):
        NotificationCreate(source="custom", session_id="s", title="Update", body="Done", metadata={"kind": ["meeting"]})
    with pytest.raises(ValidationError):
        HookPayload(metadata={"raw": {"tool_name": ["Read"]}})


def test_json_budgets_use_utf8_bytes_and_depth():
    validate_json_budget({"text": "你好"}, max_bytes=17)
    with pytest.raises(ValueError, match="byte"):
        validate_json_budget({"text": "你好"}, max_bytes=16)
    value = "text"
    for _ in range(9):
        value = {"child": value}
    with pytest.raises(ValueError, match="depth"):
        validate_json_budget(value)


@pytest.mark.parametrize("declared", [False, True])
def test_request_body_limit_checks_small_chunks_before_application(declared):
    # Tiny injected budgets exercise the middleware without network or load tests.
    async def scenario():
        messages = iter([{"type": "http.request", "body": b"ab", "more_body": True},
                         {"type": "http.request", "body": b"cde", "more_body": False}])
        sent, called = [], []
        async def receive():
            return next(messages)
        async def send(message):
            sent.append(message)
        async def app(scope, receive, send):
            called.append(await receive())
        scope = {"type": "http", "method": "POST", "headers": [(b"content-length", b"5")] if declared else []}
        await RequestBodyLimitMiddleware(app, max_bytes=4)(scope, receive, send)
        assert sent[0]["status"] == 413
        assert not called
    asyncio.run(scenario())


def test_publication_budgets_persist_and_reset_independently(tmp_path, monkeypatch):
    now = utc_now().replace(hour=12, minute=0, second=0, microsecond=0)
    monkeypatch.setattr("app.storage.utc_now", lambda: now)
    monkeypatch.setenv("SESSION_NOTIFY_PUBLISH_PER_MINUTE", "2")
    monkeypatch.setenv("SESSION_NOTIFY_PUBLISH_BYTES_PER_DAY", "10")
    path = tmp_path / "budget.db"
    storage = Storage(path)
    device = storage.bind_device("Desktop", DevicePlatform.windows).device
    storage.admit_publication(device.id, 4)
    storage.admit_publication(device.id, 4)
    storage.close()
    storage = Storage(path)
    try:
        with pytest.raises(PublishLimitError, match="limit") as limited:
            storage.admit_publication(device.id, 1)
        assert limited.value.code == "publish_rate_limited"
        now += timedelta(minutes=1)
        with pytest.raises(PublishLimitError) as daily:
            storage.admit_publication(device.id, 3)
        assert daily.value.code == "publish_daily_quota"
        other = storage.bind_device("Phone", DevicePlatform.android).device
        storage.admit_publication(other.id, 4)
        now += timedelta(days=1)
        storage.admit_publication(device.id, 4)
    finally:
        storage.close()


def test_request_body_at_limit_reaches_application_unchanged():
    async def scenario():
        messages = iter([{"type": "http.request", "body": b"ab", "more_body": True},
                         {"type": "http.request", "body": b"cd", "more_body": False}])
        received = []
        async def receive():
            return next(messages)
        async def send(message):
            pass
        async def app(scope, receive, send):
            received.append(await receive())
        await RequestBodyLimitMiddleware(app, max_bytes=4)(
            {"type": "http", "method": "POST", "headers": []}, receive, send)
        assert received == [{"type": "http.request", "body": b"abcd", "more_body": False}]
    asyncio.run(scenario())


def test_publish_limits_leave_reads_and_acknowledgements_available(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_PUBLISH_PER_MINUTE", "1")
    with TestClient(create_app(tmp_path / "api.db")) as client:
        device = client.post("/api/v1/devices/bind", json={"name": "Desktop", "platform": "windows"}).json()
        headers = {"Authorization": "Bearer " + device["access_token"]}
        payload = {"source": "custom", "session_id": "s", "title": "Update", "body": "Done",
                   "metadata": {"localOnly": True, "tag": "work"}}
        created = client.post("/api/v1/notifications", headers=headers, json=payload)
        assert created.status_code == 200
        assert created.json()["metadata"] == {"tag": "work"}
        limited = client.post("/api/v1/hooks/custom", headers=headers, json={"message": "Done"})
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) >= 1
        assert len(client.get("/api/v1/notifications", headers=headers).json()) == 1
        assert client.post("/api/v1/notifications/" + created.json()["id"] + "/ack", headers=headers, json={}).status_code == 200
