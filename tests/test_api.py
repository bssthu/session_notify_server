from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import utc_now


def bind(client: TestClient, name: str = "desktop", platform: str = "windows") -> str:
    response = client.post("/api/v1/devices/bind", json={"name": name, "platform": platform})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def bind_tokens(client: TestClient, name: str = "desktop", platform: str = "windows") -> dict:
    response = client.post("/api/v1/devices/bind", json={"name": name, "platform": platform})
    assert response.status_code == 200, response.text
    return response.json()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_create_list_and_ack_notification(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    tokens = bind_tokens(client, name="WORKSTATION-01", platform="windows")
    token = tokens["access_token"]

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
    assert notification["origin_device_id"] == tokens["device"]["id"]
    assert notification["origin_device_name"] == "WORKSTATION-01"
    assert notification["origin_device_platform"] == "windows"

    listed = client.get("/api/v1/notifications", headers=auth(token))
    assert [item["id"] for item in listed.json()] == [notification["id"]]
    assert listed.json()[0]["origin_device_name"] == "WORKSTATION-01"

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


def test_remote_clients_see_notification_origin_device(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    desktop = bind_tokens(client, name="Desktop", platform="windows")
    phone = bind_tokens(client, name="Pixel", platform="android")

    created = client.post(
        "/api/v1/notifications",
        headers=auth(desktop["access_token"]),
        json={
            "source": "codex",
            "session_id": "s-origin",
            "title": "Codex needs confirmation",
            "body": "Allow npm test?",
            "level": "critical",
        },
    )
    assert created.status_code == 200, created.text

    listed = client.get("/api/v1/notifications", headers=auth(phone["access_token"]))
    assert listed.status_code == 200, listed.text
    notification = listed.json()[0]
    assert notification["origin_device_id"] == desktop["device"]["id"]
    assert notification["origin_device_name"] == "Desktop"
    assert notification["origin_device_platform"] == "windows"


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
    tokens = bind_tokens(client, name="Hook Host", platform="windows")
    token = tokens["access_token"]

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
    assert hook.json()["origin_device_id"] == tokens["device"]["id"]
    assert hook.json()["origin_device_name"] == "Hook Host"

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


def _hook_payload(event_name, session_id, command, *, event_type=None, cwd="I:/Projects/x", tool_name="Bash"):
    if event_name == "PermissionRequest":
        event_type = event_type or "approval_requested"
    else:
        event_type = event_type or "completed"
    return {
        "hook_event_name": event_name,
        "event_type": event_type,
        "hook_status": event_type,
        "session_id": session_id,
        "cwd": cwd,
        "tool_name": tool_name,
        "metadata": {"raw": {"command": command, "cwd": cwd, "tool_name": tool_name}},
    }


def test_posttooluse_resolves_matching_permission_request(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    perm = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PermissionRequest", "s-perm", "npm test"))
    assert perm.status_code == 200, perm.text
    assert perm.json()["title"] == "claude needs confirmation"
    perm_id = perm.json()["id"]

    post = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PostToolUse", "s-perm", "npm test"))
    assert post.status_code == 200, post.text

    active = client.get("/api/v1/notifications", headers=auth(token)).json()
    assert perm_id not in [item["id"] for item in active]
    assert "claude needs confirmation" not in [item["title"] for item in active]
    # PostToolUse 自身的 completed 通知仍是 active(服务端不 suppress)
    assert "claude completed" in [item["title"] for item in active]

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    ack_events = [e for e in events if e["event_type"] == "notification.acknowledged"]
    assert len(ack_events) == 1
    assert ack_events[0]["notification_id"] == perm_id
    assert ack_events[0]["reason"] == "auto_resolved"


def test_posttooluse_without_match_is_noop(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    post = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PostToolUse", "s-alone", "npm test"))
    assert post.status_code == 200, post.text

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    assert all(e["event_type"] != "notification.acknowledged" for e in events)
    assert len([item for item in client.get("/api/v1/notifications", headers=auth(token)).json()]) == 1


def test_unrelated_permission_request_not_resolved(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    matched = client.post("/api/v1/hooks/claude", headers=auth(token),
                          json=_hook_payload("PermissionRequest", "s-shared", "npm test"))
    other = client.post("/api/v1/hooks/claude", headers=auth(token),
                        json=_hook_payload("PermissionRequest", "s-shared", "npm run build"))
    assert matched.status_code == 200 and other.status_code == 200

    post = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PostToolUse", "s-shared", "npm test"))
    assert post.status_code == 200, post.text

    active_ids = {item["id"] for item in client.get("/api/v1/notifications", headers=auth(token)).json()}
    assert matched.json()["id"] not in active_ids
    assert other.json()["id"] in active_ids

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    ack_events = [e for e in events if e["event_type"] == "notification.acknowledged"]
    assert len(ack_events) == 1
    assert ack_events[0]["notification_id"] == matched.json()["id"]


def test_long_command_pairing_aligns_via_raw(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    long_command = "echo " + "x" * 500

    perm = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PermissionRequest", "s-long", long_command))
    assert perm.status_code == 200, perm.text
    perm_id = perm.json()["id"]

    post = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PostToolUse", "s-long", long_command))
    assert post.status_code == 200, post.text

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    ack_events = [e for e in events if e["event_type"] == "notification.acknowledged"]
    assert len(ack_events) == 1
    assert ack_events[0]["notification_id"] == perm_id
    assert perm_id not in [item["id"] for item in client.get("/api/v1/notifications", headers=auth(token)).json()]


def test_hook_notifications_get_default_ttl(tmp_path):
    from datetime import datetime

    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    resp = client.post("/api/v1/hooks/claude", headers=auth(token), json={
        "hook_event_name": "Stop",
        "last_assistant_message": "done",
        "session_id": "s-ttl",
    })
    assert resp.status_code == 200, resp.text
    expires_at = resp.json()["expires_at"]
    assert expires_at is not None
    expires = datetime.fromisoformat(expires_at)
    delta = expires - datetime.now(expires.tzinfo)
    assert timedelta(hours=23, minutes=55) < delta < timedelta(hours=24, minutes=5)


def test_backfill_expires_stale_hook_history(tmp_path):
    from app.storage import Storage, _dt
    from app.schemas import NotificationCreate, NotificationLevel, NotificationStatus

    storage = Storage(tmp_path / "s.db")
    stale, _ = storage.create_notification(NotificationCreate(
        source="claude", session_id="s-old", title="claude needs confirmation",
        body="stale history", level=NotificationLevel.critical,
        metadata={"hook_event_name": "PermissionRequest"},
    ))
    user_notif, _ = storage.create_notification(NotificationCreate(
        source="session", session_id="s-user", title="Standup",
        body="meeting", level=NotificationLevel.important,
        metadata={},
    ))
    # 模拟历史堆积:把 stale 的 created_at 改到 25h 前(expires_at 仍为 NULL)
    with storage._lock, storage._conn:
        storage._conn.execute(
            "UPDATE notifications SET created_at = ? WHERE id = ?",
            (_dt(utc_now() - timedelta(hours=25)), stale.id),
        )

    backfilled = storage.backfill_hook_expiry(timedelta(hours=24))
    assert backfilled == 1  # 只有 hook 来源的 stale 被回填,非 hook 通知不动

    events = storage.expire_due_notifications()
    assert any(e.notification_id == stale.id for e in events)
    active_ids = {n.id for n in storage.list_notifications([NotificationStatus.active])}
    assert stale.id not in active_ids        # 25h 前 + 24h TTL = 已过期
    assert user_notif.id in active_ids       # 非 hook 通知不受 TTL 影响
    storage.close()
