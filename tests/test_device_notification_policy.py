import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import DevicePlatform, NotificationCreate
from app.storage import Storage


def auth(device):
    return {"Authorization": "Bearer " + device["access_token"]}


@pytest.fixture
def system(tmp_path):
    app = create_app(tmp_path / "policy.db")
    with TestClient(app) as client:
        devices = [client.post("/api/v1/devices/bind", json={
            "name": name, "platform": "windows",
        }).json() for name in ("Admin", "Member", "Guest")]
        admin, member, guest = devices
        assert client.patch("/api/v1/devices/" + guest["device"]["id"], headers=auth(admin),
                            json={"role": "guest"}).status_code == 200
        yield client, app.state.storage, admin, member, guest


def update(client, actor, target, **values):
    return client.patch("/api/v1/devices/" + target["device"]["id"], headers=auth(actor), json=values)


def hook(client, device, delivery="one", **extra):
    return client.post("/api/v1/hooks/claude", headers=auth(device), json={
        "session_id": "policy-session", "hook_event_name": "Stop", "event_type": "completed",
        "message": "Finished", "metadata": {"delivery_id": delivery}, **extra,
    })


@pytest.mark.parametrize("field,value", [("hook_notifications_enabled", False), ("silent_notifications", True)])
def test_defaults_and_server_enforced_ownership(system, field, value):
    client, _, admin, member, guest = system
    for device in (admin, member, guest):
        policy = client.get("/api/v1/devices/me/notification-policy", headers=auth(device))
        assert policy.json() == {"hook_notifications_enabled": True, "silent_notifications": False}
    for actor in (member, guest):
        assert update(client, actor, admin, **{field: value}).status_code == 403
        assert update(client, actor, actor, **{field: value}).json()[field] is value
        assert update(client, admin, actor, **{field: not value}).json()[field] is not value


def test_silent_send_is_atomic_visible_in_authorized_history_and_deduplicated(system):
    client, storage, admin, member, guest = system
    assert update(client, member, member, silent_notifications=True).status_code == 200
    with client.websocket_connect("/api/v1/ws", headers=auth(admin)) as websocket:
        sent = hook(client, member)
        assert sent.status_code == 200, sent.text
        item = sent.json()
        assert item["status"] == "acknowledged"
        event = websocket.receive_json()
        assert event["event_type"] == "notification.acknowledged"
        assert event["reason"] == "silent_send"
        assert event["notification_id"] == item["id"]
        assert hook(client, member).json()["id"] == item["id"]
        normal = hook(client, admin, "normal")
        assert normal.json()["status"] == "active"
        assert websocket.receive_json()["notification"]["id"] == normal.json()["id"]
    for viewer in (admin, member):
        active = client.get("/api/v1/notifications", headers=auth(viewer)).json()
        assert item["id"] not in {n["id"] for n in active}
        history = client.get("/api/v1/notifications/recent", headers=auth(viewer)).json()["items"]
        assert next(n for n in history if n["id"] == item["id"])["status"] == "acknowledged"
        events = client.get("/api/v1/events", headers=auth(viewer)).json()["events"]
        assert not any(e["event_type"] == "notification.created" and
                       e["notification"]["id"] == item["id"] for e in events)
    assert client.get("/api/v1/notifications/recent", headers=auth(guest)).json()["items"] == []
    assert storage._conn.execute("SELECT reason FROM acks WHERE notification_id = ?", (item["id"],)).fetchone()[0] == "silent_send"


def test_send_off_wins_over_silent_and_does_not_affect_receiving_or_manual_send(system):
    client, _, admin, member, _ = system
    assert update(client, admin, member, hook_notifications_enabled=False, silent_notifications=True).status_code == 200
    assert hook(client, member).json() is None
    assert client.get("/api/v1/notifications/recent", headers=auth(admin)).json()["items"] == []
    incoming = hook(client, admin).json()
    assert client.get("/api/v1/notifications", headers=auth(member)).json()[0]["id"] == incoming["id"]
    manual = client.post("/api/v1/notifications", headers=auth(member), json={
        "source": "manual", "session_id": "manual", "title": "Manual", "body": "Still allowed",
    })
    assert manual.status_code == 200 and manual.json()["status"] == "acknowledged"
    assert update(client, member, member, hook_notifications_enabled=True, silent_notifications=False).status_code == 200
    assert hook(client, member, "enabled").json()["status"] == "active"


def test_policy_read_inside_publication_ignores_stale_device_snapshot(system):
    client, storage, admin, member, _ = system
    stale = storage.authenticate(member["access_token"])
    request = NotificationCreate(source="test", session_id="s", title="t", body="b")
    update(client, admin, member, hook_notifications_enabled=False)
    assert storage.create_notification(request, stale, enforce_hook_policy=True) == (None, None)
    update(client, admin, member, hook_notifications_enabled=True, silent_notifications=True)
    item, event = storage.create_notification(request, stale, enforce_hook_policy=True)
    assert item.status == "acknowledged" and event.event_type == "notification.acknowledged"


def test_correlated_approval_cannot_emit_a_created_event_when_silent(system):
    client, _, admin, member, _ = system
    update(client, member, member, silent_notifications=True)
    first = hook(client, member, "approval-first", hook_event_name="PermissionRequest",
                 event_type="approval_requested", tool_name="Bash", tool_input={"command": "pwd"}).json()
    second = hook(client, member, "approval-second", hook_event_name="Notification",
                  event_type="approval_requested", notification_type="permission_prompt",
                  tool_name="Bash", tool_input={"command": "pwd"}).json()
    assert first["status"] == second["status"] == "acknowledged"
    events = client.get("/api/v1/events", headers=auth(admin)).json()["events"]
    assert all(e["event_type"] != "notification.created" for e in events)


def test_async_question_late_ambiguity_cannot_reopen_silent_notifications(system):
    from datetime import timedelta
    from app.schemas import utc_now
    from test_codex_async_questions import ask, answer

    client, _, admin, member, _ = system
    update(client, member, member, silent_notifications=True)
    now = utc_now() - timedelta(seconds=10)
    for payload in (ask(at=now), answer(at=now + timedelta(seconds=2)),
                    ask(call="call-2", at=now + timedelta(seconds=1))):
        response = client.post("/api/v1/hooks/codex", headers=auth(member), json=payload)
        assert response.status_code == 200, response.text
        assert response.json() is None or response.json()["status"] == "acknowledged"
    assert client.get("/api/v1/notifications", headers=auth(admin)).json() == []
    events = client.get("/api/v1/events", headers=auth(admin)).json()["events"]
    assert all(e["event_type"] != "notification.created" for e in events)


def test_existing_database_migrates_with_defaults_and_persists_settings(tmp_path):
    path = tmp_path / "old.db"
    storage = Storage(path)
    device = storage.bind_device("Old", DevicePlatform.windows).device
    with storage._conn:
        storage._conn.execute("ALTER TABLE devices DROP COLUMN hook_notifications_enabled")
        storage._conn.execute("ALTER TABLE devices DROP COLUMN silent_notifications")
    storage.close()
    storage = Storage(path)
    migrated = storage.list_devices()[0]
    assert migrated.hook_notifications_enabled and not migrated.silent_notifications
    storage.update_device(device.id, hook_notifications_enabled=False, silent_notifications=True)
    storage.close()
    storage = Storage(path)
    saved = storage.list_devices()[0]
    assert not saved.hook_notifications_enabled and saved.silent_notifications
    storage.close()
