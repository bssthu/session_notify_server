from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import utc_now


def bind(client: TestClient, name: str = "desktop", platform: str = "windows") -> str:
    response = client.post("/api/v1/devices/bind", json={"name": name, "platform": platform})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def bind_tokens(client: TestClient, name: str = "desktop", platform: str = "windows") -> dict[str, str]:
    response = client.post("/api/v1/devices/bind", json={"name": name, "platform": platform})
    assert response.status_code == 200, response.text
    return response.json()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_create_list_and_ack_notification(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    created = client.post(
        "/api/v1/notifications",
        headers=auth(token),
        json={
            "source": "codex",
            "session_id": "s-1",
            "title": "Codex needs confirmation",
            "body": "Allow npm test?",
            "level": "critical",
            "requires_ack": True,
            "metadata": {"cwd": "I:/Projects/session_notify"},
        },
    )
    assert created.status_code == 200, created.text
    notification = created.json()
    assert notification["status"] == "active"
    assert notification["level"] == "critical"

    listed = client.get("/api/v1/notifications", headers=auth(token))
    assert [item["id"] for item in listed.json()] == [notification["id"]]

    acked = client.post(
        f"/api/v1/notifications/{notification['id']}/ack",
        headers=auth(token),
        json={"reason": "user_confirmed"},
    )
    assert acked.status_code == 200, acked.text
    assert acked.json()["already_acknowledged"] is False
    assert acked.json()["notification"]["status"] == "acknowledged"

    acked_again = client.post(
        f"/api/v1/notifications/{notification['id']}/ack",
        headers=auth(token),
        json={"reason": "user_confirmed"},
    )
    assert acked_again.status_code == 200
    assert acked_again.json()["already_acknowledged"] is True

    active = client.get("/api/v1/notifications", headers=auth(token))
    assert active.json() == []


def test_event_pull_and_websocket_push(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    with client.websocket_connect(f"/api/v1/ws?token={token}") as websocket:
        response = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json={
                "source": "claude",
                "session_id": "s-2",
                "title": "Claude completed",
                "body": "Refactor finished",
                "level": "success",
            },
        )
        assert response.status_code == 200, response.text
        pushed = websocket.receive_json()
        assert pushed["schema_version"] == 1
        assert pushed["event_type"] == "notification.created"
        assert pushed["notification"]["title"] == "Claude completed"

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    assert len(events) == 1
    assert events[0]["event_id"] == pushed["event_id"]

    after = client.get(
        "/api/v1/events",
        headers=auth(token),
        params={"since_event_id": pushed["event_id"]},
    ).json()["events"]
    assert after == []


def test_websocket_accepts_authorization_header(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    with client.websocket_connect("/api/v1/ws", headers=auth(token)) as websocket:
        response = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json={
                "source": "codex",
                "session_id": "s-ws-header",
                "title": "Header auth works",
                "body": "WebSocket accepted Authorization header",
                "level": "info",
            },
        )
        assert response.status_code == 200, response.text
        assert websocket.receive_json()["notification"]["title"] == "Header auth works"


def test_refresh_token_rotates_access_token(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    tokens = bind_tokens(client)
    old_access = tokens["access_token"]
    refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh.status_code == 200, refresh.text
    new_access = refresh.json()["access_token"]
    assert new_access != old_access

    old_auth = client.get("/api/v1/notifications", headers=auth(old_access))
    assert old_auth.status_code == 401
    new_auth = client.get("/api/v1/notifications", headers=auth(new_access))
    assert new_auth.status_code == 200

    bad = client.post("/api/v1/auth/refresh", json={"refresh_token": "bad"})
    assert bad.status_code == 401


def test_android_device_bind_can_sync_and_refresh(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    tokens = bind_tokens(client, name="Pixel", platform="android")
    assert tokens["device"]["platform"] == "android"
    assert tokens["device"]["name"] == "Pixel"

    listed = client.get("/api/v1/notifications", headers=auth(tokens["access_token"]))
    assert listed.status_code == 200, listed.text
    assert listed.json() == []

    refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh.status_code == 200, refresh.text
    refreshed = refresh.json()
    assert refreshed["device"]["platform"] == "android"
    assert refreshed["access_token"] != tokens["access_token"]

    refreshed_list = client.get("/api/v1/notifications", headers=auth(refreshed["access_token"]))
    assert refreshed_list.status_code == 200, refreshed_list.text


def test_hook_mapping_and_expiry(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    hook = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json={
            "event_type": "approval_requested",
            "prompt": "Run cargo test?",
            "session_id": "s-3",
        },
    )
    assert hook.status_code == 200, hook.text
    assert hook.json()["level"] == "critical"
    assert hook.json()["title"] == "codex needs confirmation"

    expired = client.post(
        "/api/v1/notifications",
        headers=auth(token),
        json={
            "source": "codex",
            "session_id": "s-4",
            "title": "Old reminder",
            "body": "Expired already",
            "level": "info",
            "expires_at": (utc_now() - timedelta(seconds=1)).isoformat(),
        },
    )
    assert expired.status_code == 200

    active = client.get("/api/v1/notifications", headers=auth(token)).json()
    assert [item["title"] for item in active] == ["codex needs confirmation"]


def test_official_hook_event_mapping(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    completed = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json={
            "hook_event_name": "Stop",
            "last_assistant_message": "Refactor finished.",
            "session_id": "s-stop",
            "cwd": "I:/Projects/session_notify",
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["level"] == "success"
    assert completed.json()["title"] == "claude completed"
    assert completed.json()["body"] == "Refactor finished."
    assert completed.json()["metadata"]["hook_event_name"] == "Stop"
    assert completed.json()["metadata"]["cwd"] == "I:/Projects/session_notify"
    assert completed.json()["metadata"]["body_generated"] is False

    generic_completed = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json={
            "hook_event_name": "TaskCompleted",
            "session_id": "s-task-completed",
        },
    )
    assert generic_completed.status_code == 200, generic_completed.text
    assert generic_completed.json()["level"] == "success"
    assert generic_completed.json()["title"] == "claude completed"
    assert generic_completed.json()["body"] == "Session event received."
    assert generic_completed.json()["metadata"]["body_generated"] is True

    permission = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json={
            "hook_event_name": "Notification",
            "notification_type": "permission_prompt",
            "message": "Claude needs your permission",
            "session_id": "s-permission",
        },
    )
    assert permission.status_code == 200, permission.text
    assert permission.json()["level"] == "critical"
    assert permission.json()["title"] == "claude needs confirmation"


def test_requires_authorization(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    response = client.get("/api/v1/notifications")
    assert response.status_code == 401
