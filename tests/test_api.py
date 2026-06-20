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


def test_device_management_updates_notification_delivery_and_revokes(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    desktop = bind_tokens(client, name="Desktop", platform="windows")
    phone = bind_tokens(client, name="Pixel", platform="android")

    devices = client.get("/api/v1/devices", headers=auth(desktop["access_token"]))
    assert devices.status_code == 200, devices.text
    assert [item["name"] for item in devices.json()] == ["Desktop", "Pixel"]
    assert all(item["notifications_enabled"] is True for item in devices.json())

    renamed = client.patch(
        f"/api/v1/devices/{desktop['device']['id']}",
        headers=auth(desktop["access_token"]),
        json={"name": "Workstation"},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "Workstation"

    disabled = client.patch(
        f"/api/v1/devices/{phone['device']['id']}",
        headers=auth(desktop["access_token"]),
        json={"notifications_enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["notifications_enabled"] is False

    created = client.post(
        "/api/v1/notifications",
        headers=auth(desktop["access_token"]),
        json={
            "source": "codex",
            "session_id": "s-device-filter",
            "title": "Filtered notification",
            "body": "Disabled devices should not receive this.",
            "level": "info",
        },
    )
    assert created.status_code == 200, created.text

    disabled_list = client.get("/api/v1/notifications", headers=auth(phone["access_token"]))
    assert disabled_list.status_code == 200, disabled_list.text
    assert disabled_list.json() == []

    disabled_events = client.get("/api/v1/events", headers=auth(phone["access_token"]))
    assert disabled_events.status_code == 200, disabled_events.text
    assert disabled_events.json()["events"][0]["event_type"] == "notification.created"
    assert disabled_events.json()["events"][0]["notification"] is None

    enabled = client.patch(
        f"/api/v1/devices/{phone['device']['id']}",
        headers=auth(desktop["access_token"]),
        json={"notifications_enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["notifications_enabled"] is True
    enabled_list = client.get("/api/v1/notifications", headers=auth(phone["access_token"]))
    assert [item["id"] for item in enabled_list.json()] == [created.json()["id"]]

    revoked = client.delete(
        f"/api/v1/devices/{phone['device']['id']}",
        headers=auth(desktop["access_token"]),
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_at"] is not None

    devices_after_revoke = client.get("/api/v1/devices", headers=auth(desktop["access_token"]))
    assert [item["id"] for item in devices_after_revoke.json()] == [desktop["device"]["id"]]
    assert client.get("/api/v1/notifications", headers=auth(phone["access_token"])).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": phone["refresh_token"]}).status_code == 401


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


def test_session_stop_acknowledges_pending_permission(tmp_path):
    # 用户在 CLI 拒绝权限 → 不发 PostToolUse → 会话 Stop 到达时按会话兜底清理,
    # 避免残留 active 被重启 reload 重显。
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    perm = client.post("/api/v1/hooks/codex", headers=auth(token),
                       json=_hook_payload("PermissionRequest", "s-deny", "rm -rf x"))
    assert perm.status_code == 200, perm.text
    perm_id = perm.json()["id"]

    stop = client.post("/api/v1/hooks/codex", headers=auth(token),
                       json=_hook_payload("Stop", "s-deny", ""))
    assert stop.status_code == 200, stop.text

    active = client.get("/api/v1/notifications", headers=auth(token)).json()
    assert perm_id not in [item["id"] for item in active]
    assert "codex needs confirmation" not in [item["title"] for item in active]

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    finalize_events = [
        e for e in events
        if e["event_type"] == "notification.acknowledged" and e["reason"] == "session_finalized"
    ]
    assert any(e["notification_id"] == perm_id for e in finalize_events)


def test_session_stop_acknowledges_notification_permission_prompt(tmp_path):
    # claude 权限请求的另一形态:Notification hook + notification_type=permission_prompt,
    # hook_event_name=Notification(非 permissionrequest)。清理按 title(needs confirmation)
    # 判定,也要覆盖这类,否则它会残留 active 被重启 reload 重显。
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    resp = client.post("/api/v1/hooks/claude", headers=auth(token), json={
        "hook_event_name": "Notification",
        "event_type": "approval_requested",
        "hook_status": "approval_requested",
        "notification_type": "permission_prompt",
        "session_id": "s-notif",
        "message": "Claude needs your permission to use Bash",
        "cwd": "I:/Projects/x",
        "tool_name": "Bash",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["title"] == "claude needs confirmation"
    nid = resp.json()["id"]

    client.post("/api/v1/hooks/claude", headers=auth(token),
                json=_hook_payload("Stop", "s-notif", ""))

    active_ids = {item["id"] for item in client.get("/api/v1/notifications", headers=auth(token)).json()}
    assert nid not in active_ids


def test_session_finalize_does_not_touch_other_sessions(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    p_a = client.post("/api/v1/hooks/claude", headers=auth(token),
                      json=_hook_payload("PermissionRequest", "s-a", "npm a")).json()["id"]
    p_b = client.post("/api/v1/hooks/claude", headers=auth(token),
                      json=_hook_payload("PermissionRequest", "s-b", "npm b")).json()["id"]

    client.post("/api/v1/hooks/claude", headers=auth(token),
                json=_hook_payload("Stop", "s-a", ""))

    active_ids = {item["id"] for item in client.get("/api/v1/notifications", headers=auth(token)).json()}
    assert p_a not in active_ids   # s-a 会话结束,其 permission 被清理
    assert p_b in active_ids       # s-b 会话不受影响


def test_permission_request_uses_short_ttl(tmp_path, monkeypatch):
    import app.main
    from datetime import datetime

    monkeypatch.setattr(app.main, "HOOK_PERMISSION_TTL", timedelta(minutes=5))
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    resp = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PermissionRequest", "s-ttl", "npm test"))
    assert resp.status_code == 200, resp.text
    expires = datetime.fromisoformat(resp.json()["expires_at"])
    delta = expires - datetime.now(expires.tzinfo)
    assert timedelta(minutes=4, seconds=30) < delta < timedelta(minutes=5, seconds=30)


def test_lifespan_cleans_legacy_permission_requests(tmp_path):
    from app.storage import Storage
    from app.schemas import EventType, NotificationCreate, NotificationLevel, NotificationStatus

    db_path = tmp_path / "s.db"
    storage = Storage(db_path)
    legacy, _ = storage.create_notification(NotificationCreate(
        source="codex", session_id="s-old", title="codex needs confirmation",
        body="stale history", level=NotificationLevel.critical,
        expires_at=utc_now() + timedelta(hours=24),   # 未来,不会被 expire_due 清掉
        metadata={"hook_event_name": "PermissionRequest"},
    ))
    storage.close()

    # TestClient 作为 context manager 才触发 lifespan startup → 迁移清理
    client = TestClient(create_app(db_path))
    with client:
        token = bind(client)
        active = client.get("/api/v1/notifications", headers=auth(token)).json()
        assert legacy.id not in [item["id"] for item in active]

    storage = Storage(db_path)
    assert legacy.id in {n.id for n in storage.list_notifications([NotificationStatus.acknowledged])}
    cleanup_events = [
        e for e in storage.events_after(None)
        if e.event_type == EventType.notification_acknowledged
        and e.notification_id == legacy.id
        and e.reason == "migration_cleanup"
    ]
    assert len(cleanup_events) == 1
    storage.close()

    # 幂等:再起一次 app,legacy 已非 active,迁移不再产生新事件
    with TestClient(create_app(db_path)):
        pass
    storage = Storage(db_path)
    cleanup_events2 = [
        e for e in storage.events_after(None)
        if e.event_type == EventType.notification_acknowledged
        and e.notification_id == legacy.id
        and e.reason == "migration_cleanup"
    ]
    assert len(cleanup_events2) == 1
    storage.close()


def _expire_field(app, device_id, field, *, past: bool = True, null: bool = False):
    """直接把 devices 表某 token 过期列改到过去(模拟到期)或置 NULL(模拟老库迁移态)。"""
    from app.storage import _dt
    storage = app.state.storage
    value = None if null else _dt(utc_now() - timedelta(seconds=1) if past else utc_now() + timedelta(days=1))
    with storage._lock, storage._conn:
        storage._conn.execute(
            f"UPDATE devices SET {field} = ? WHERE id = ?",  # field is internal test constant
            (value, device_id),
        )


def test_bind_response_includes_access_expiry(tmp_path):
    from datetime import datetime

    client = TestClient(create_app(tmp_path / "server.db"))
    tokens = bind_tokens(client)
    assert tokens["access_expires_at"] is not None
    expires = datetime.fromisoformat(tokens["access_expires_at"])
    delta = expires - datetime.now(expires.tzinfo)
    # 默认 access TTL = 1h
    assert timedelta(minutes=55) < delta < timedelta(hours=1, minutes=5)


def test_expired_access_token_is_rejected_and_refreshable(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    tokens = bind_tokens(client)
    old_access = tokens["access_token"]
    device_id = tokens["device"]["id"]

    assert client.get("/api/v1/notifications", headers=auth(old_access)).status_code == 200

    # access 到期 → 鉴权失败
    _expire_field(app, device_id, "access_expires_at")
    assert client.get("/api/v1/notifications", headers=auth(old_access)).status_code == 401

    # refresh 换发新 access(refresh 仍有效)→ 恢复,且新响应带新的 access_expires_at
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200, refreshed.text
    new_access = refreshed.json()["access_token"]
    assert new_access != old_access
    assert refreshed.json()["access_expires_at"] is not None
    assert client.get("/api/v1/notifications", headers=auth(new_access)).status_code == 200


def test_expired_refresh_token_requires_rebind(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    tokens = bind_tokens(client)
    _expire_field(app, tokens["device"]["id"], "refresh_expires_at")

    # refresh token 到期 → refresh 端点拒绝,需重新绑定
    refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401


def test_null_expiry_is_backward_compatible(tmp_path):
    """老库 migration 后 *_expires_at 为 NULL → 视为不过期,不强制存量设备重绑。"""
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    tokens = bind_tokens(client)
    token = tokens["access_token"]
    _expire_field(app, tokens["device"]["id"], "access_expires_at", null=True)
    _expire_field(app, tokens["device"]["id"], "refresh_expires_at", null=True)

    assert client.get("/api/v1/notifications", headers=auth(token)).status_code == 200
    refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 200


def test_pair_issue_requires_bearer(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    assert client.post("/api/v1/devices/pair/issue").status_code == 401


def test_pair_issue_and_consume_binds_new_device(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    host = bind_tokens(client, name="Host", platform="windows")

    issued = client.post("/api/v1/devices/pair/issue", headers=auth(host["access_token"]))
    assert issued.status_code == 200, issued.text
    code = issued.json()["code"]
    assert code.count("-") == 1 and len(code.replace("-", "")) == 8  # XXXX-XXXX
    assert issued.json()["expires_at"] is not None

    consumed = client.post("/api/v1/devices/pair/consume", json={
        "code": code, "name": "Pixel", "platform": "android"
    })
    assert consumed.status_code == 200, consumed.text
    bound = consumed.json()
    assert bound["device"]["name"] == "Pixel"
    assert bound["device"]["platform"] == "android"
    assert bound["access_token"] and bound["refresh_token"]
    assert client.get("/api/v1/notifications", headers=auth(bound["access_token"])).status_code == 200


def test_pair_consume_invalid_code_rejected(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    bad = client.post("/api/v1/devices/pair/consume", json={
        "code": "NOPE-CODE", "name": "X", "platform": "android"
    })
    assert bad.status_code == 401


def test_pair_code_is_one_shot(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    host = bind_tokens(client)
    code = client.post("/api/v1/devices/pair/issue", headers=auth(host["access_token"])).json()["code"]

    first = client.post("/api/v1/devices/pair/consume", json={"code": code, "name": "A", "platform": "windows"})
    assert first.status_code == 200
    second = client.post("/api/v1/devices/pair/consume", json={"code": code, "name": "B", "platform": "windows"})
    assert second.status_code == 401


def test_pair_code_expiry_rejects(tmp_path):
    from app.storage import _dt

    client = TestClient(create_app(tmp_path / "server.db"))
    host = bind_tokens(client)
    code = client.post("/api/v1/devices/pair/issue", headers=auth(host["access_token"])).json()["code"]
    storage = client.app.state.storage
    with storage._lock, storage._conn:
        storage._conn.execute("UPDATE pair_codes SET expires_at = ?", (_dt(utc_now() - timedelta(seconds=1)),))

    expired = client.post("/api/v1/devices/pair/consume", json={"code": code, "name": "A", "platform": "windows"})
    assert expired.status_code == 401


def test_strict_mode_first_device_binds_then_bare_bind_blocked(tmp_path, monkeypatch):
    # conftest 默认 easy;此处显式切 strict 验证 bootstrap 门禁
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "strict")
    client = TestClient(create_app(tmp_path / "server.db"))

    first = client.post("/api/v1/devices/bind", json={"name": "Host", "platform": "windows"})
    assert first.status_code == 200, first.text
    host = first.json()

    # 已有已绑设备后,裸 bind 被拒(必须走配对码)
    assert client.post("/api/v1/devices/bind", json={"name": "Sneak", "platform": "windows"}).status_code == 401

    code = client.post("/api/v1/devices/pair/issue", headers=auth(host["access_token"])).json()["code"]
    consumed = client.post("/api/v1/devices/pair/consume", json={"code": code, "name": "Pixel", "platform": "android"})
    assert consumed.status_code == 200


def test_easy_mode_allows_multiple_bare_binds(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "easy")
    client = TestClient(create_app(tmp_path / "server.db"))
    assert client.post("/api/v1/devices/bind", json={"name": "A", "platform": "windows"}).status_code == 200
    assert client.post("/api/v1/devices/bind", json={"name": "B", "platform": "windows"}).status_code == 200


def test_strict_mode_rebind_with_old_refresh_token(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "strict")
    client = TestClient(create_app(tmp_path / "server.db"))
    first = client.post("/api/v1/devices/bind", json={"name": "Host", "platform": "windows"})
    assert first.status_code == 200, first.text
    old_refresh = first.json()["refresh_token"]
    device_id = first.json()["device"]["id"]

    # 裸 bind(无 refresh)被拒
    assert client.post("/api/v1/devices/bind", json={"name": "Sneak", "platform": "windows"}).status_code == 401

    # 带有效旧 refresh_token → 本机 rebind 放行:同一设备、换发新 token、轮换 refresh
    rebound = client.post("/api/v1/devices/bind", json={
        "name": "Host", "platform": "windows", "refresh_token": old_refresh
    })
    assert rebound.status_code == 200, rebound.text
    assert rebound.json()["device"]["id"] == device_id
    assert rebound.json()["refresh_token"] != old_refresh

    # 旧 refresh 已轮换失效
    again = client.post("/api/v1/devices/bind", json={
        "name": "Host", "platform": "windows", "refresh_token": old_refresh
    })
    assert again.status_code == 401


def test_revoke_all_devices_via_storage(tmp_path):
    from app.schemas import DevicePlatform
    from app.storage import Storage
    storage = Storage(tmp_path / "s.db")
    storage.bind_device("A", DevicePlatform.windows)
    storage.bind_device("B", DevicePlatform.android)
    assert storage.has_any_device()
    assert storage.revoke_all_devices() == 2
    assert not storage.has_any_device()
    storage.close()


def test_reset_endpoint_rejects_non_localhost(tmp_path):
    # TestClient 的 client.host 非 127.0.0.1,reset 端点应 403(只允许本机调用)。
    client = TestClient(create_app(tmp_path / "server.db"))
    bind_tokens(client, name="A")
    response = client.post("/api/v1/devices/reset")
    assert response.status_code == 403


def test_reset_devices_script_revokes_all(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    from app.schemas import DevicePlatform
    from app.storage import Storage

    db = tmp_path / "s.db"
    storage = Storage(db)
    storage.bind_device("A", DevicePlatform.windows)
    storage.bind_device("B", DevicePlatform.android)
    storage.close()

    script = Path(__file__).resolve().parent.parent / "scripts" / "reset_devices.py"
    result = subprocess.run(
        [sys.executable, str(script), "--yes", "--db", str(db)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "已撤销 2 台设备" in result.stdout

    storage = Storage(db)
    assert not storage.has_any_device()
    storage.close()
