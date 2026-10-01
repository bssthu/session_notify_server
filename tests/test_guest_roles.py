from datetime import timedelta

import pytest
from starlette.websockets import WebSocketDisconnect

from app.schemas import NotificationCreate, utc_now
from test_device_roles import headers, invite, system


def post_notification(client, device, title="Local", **extra):
    response = client.post("/api/v1/notifications", headers=headers(device), json={
        "source": title, "session_id": "shared-session", "title": title, "body": title,
        "metadata": {"tag": title}, **extra,
    })
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("platform", ["windows", "android"])
def test_guest_binding_self_management_and_presence_do_not_expose_peers(system, platform):
    client, _, admin, _ = system
    guest = invite(client, admin, role="guest", platform=platform)
    guest_id = guest["device"]["id"]
    auth = headers(guest)
    client.post("/api/v1/devices/me/presence", headers=headers(admin), json={"session_state": "unlocked"})
    listed = client.get("/api/v1/devices", headers=auth).json()
    assert [item["id"] for item in listed] == [guest_id]
    assert listed[0]["role"] == "guest"
    summary = client.get("/api/v1/devices/presence", headers=auth).json()
    assert summary["registered_windows"] == (1 if platform == "windows" else 0)
    assert not summary["any_unlocked_windows"]
    assert all(item["device_id"] == guest_id for item in summary["windows_devices"])
    if platform == "windows":
        summary = client.post("/api/v1/devices/me/presence", headers=auth,
                              json={"session_state": "unlocked"}).json()
        assert summary["registered_windows"] == 1 and summary["any_unlocked_windows"]
        assert summary["windows_devices"][0]["device_id"] == guest_id
    path = "/api/v1/devices/" + guest_id
    for changes in ({"name": "Guest renamed"}, {"notifications_enabled": False}, {"notifications_enabled": True}):
        assert client.patch(path, headers=auth, json=changes).status_code == 200
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": guest["refresh_token"]}).json()
    assert refreshed["device"]["role"] == "guest"
    rebound = client.post("/api/v1/devices/bind", json={
        "name": "Guest rebound", "platform": platform, "refresh_token": guest["refresh_token"],
    }).json()
    assert rebound["device"]["id"] == guest_id and rebound["device"]["role"] == "guest"
    assert client.delete(path, headers=headers(rebound)).status_code == 200
    assert client.get("/api/v1/devices", headers=headers(rebound)).status_code == 401


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/v1/devices/pair/issue", {"role": "guest"}),
    ("POST", "/api/v1/devices/pair/status", {"code": "ABCD-2345"}),
    ("PATCH", "/api/v1/devices/{other}", {}),
    ("PATCH", "/api/v1/devices/{other}", {"name": "changed"}),
    ("PATCH", "/api/v1/devices/{other}", {"notifications_enabled": False}),
    ("DELETE", "/api/v1/devices/{other}", None),
    ("PATCH", "/api/v1/devices/{self}", {"role": "admin"}),
    ("PATCH", "/api/v1/devices/{self}", {"role": "member"}),
    ("PATCH", "/api/v1/devices/{self}", {"role": "guest"}),
])
def test_guest_cannot_manage_peers_invite_or_set_any_role(system, method, path, body):
    client, _, admin, _ = system
    guest = invite(client, admin, role="guest")
    path = path.format(other=admin["device"]["id"], self=guest["device"]["id"])
    assert client.request(method, path, headers=headers(guest), json=body).status_code == 403


def test_guest_lists_history_search_and_event_cursors_are_scoped_before_pagination(system):
    client, storage, admin, member = system
    guest = invite(client, admin, role="guest")
    other_guest = invite(client, admin, role="guest")
    storage.create_notification(NotificationCreate(source="legacy", session_id="s", title="Legacy", body="Secret"))
    post_notification(client, admin, "Secret-admin")
    own1 = post_notification(client, guest, "Local-1", origin_device_id=admin["device"]["id"])
    assert own1["origin_device_id"] == guest["device"]["id"]
    post_notification(client, member, "Secret-member")
    own2 = post_notification(client, guest, "Local-2")
    post_notification(client, other_guest, "Secret-guest")
    auth = headers(guest)
    assert [item["id"] for item in client.get("/api/v1/notifications", headers=auth).json()] == [own1["id"], own2["id"]]
    assert len(client.get("/api/v1/notifications", headers=headers(member)).json()) == 6
    page = client.get("/api/v1/notifications/recent?limit=1&visible_only=false", headers=auth).json()
    assert page["total_count"] == 2 and page["total_pages"] == 2 and page["has_more"]
    assert page["items"][0]["id"] == own2["id"]
    assert page["filter_options"]["agents"] == ["Local-1", "Local-2"]
    assert page["filter_options"]["tags"] == ["Local-1", "Local-2"]
    assert [m["id"] for m in page["filter_options"]["machines"]] == [guest["device"]["id"]]
    next_page = client.get("/api/v1/notifications/recent", headers=auth,
                           params={"cursor": page["next_cursor"], "limit": 1}).json()
    assert [item["id"] for item in next_page["items"]] == [own1["id"]]
    for params in ({"q": "Secret"}, {"machine": admin["device"]["id"]}, {"agent": "Secret-member"}, {"tag": "Secret"}):
        empty = client.get("/api/v1/notifications/recent", headers=auth, params=params).json()
        assert empty["items"] == [] and empty["total_count"] == 0
        assert "Secret" not in str(empty["filter_options"])
    events = client.get("/api/v1/events", headers=auth).json()["events"]
    assert [event["notification"]["id"] for event in events] == [own1["id"], own2["id"]]
    first, last = [event["event_id"] for event in events]
    assert client.get("/api/v1/events?limit=1", headers=auth).json()["latest_event_id"] == last
    window = client.get("/api/v1/events", headers=auth, params={"limit": 1, "since_event_id": first}).json()
    assert len(window["events"]) == 1 and not window["has_more"]
    assert window["events"][0]["event_id"] == last
    hidden_cursor = client.get("/api/v1/events?limit=1", headers=headers(admin)).json()["latest_event_id"]
    unknown = client.get("/api/v1/events", headers=auth, params={"limit": 1, "since_event_id": hidden_cursor}).json()
    assert unknown["cursor_found"] is False and unknown["latest_event_id"] == last


def test_guest_websocket_excludes_remote_creates_acks_expiry_and_presence(system):
    client, storage, admin, member = system
    guest = invite(client, admin, role="guest")
    auth = headers(guest)
    own = post_notification(client, guest)
    with client.websocket_connect("/api/v1/ws", headers=auth) as ws:
        remote = post_notification(client, admin, "Remote")
        assert client.post(f"/api/v1/notifications/{remote['id']}/ack", headers=auth, json={}).status_code == 404
        assert client.get("/api/v1/notifications", headers=headers(admin)).json()[-1]["status"] == "active"
        client.post(f"/api/v1/notifications/{remote['id']}/ack", headers=headers(member), json={})
        post_notification(client, admin, "Expired", expires_at=(utc_now() - timedelta(seconds=1)).isoformat())
        for event in storage.expire_due_notifications():
            assert not storage.should_deliver_event_to_device(event, guest["device"]["id"])
            client.portal.call(client.app.state.hub.broadcast, event,
                               storage.should_deliver_event_to_device, storage.event_for_device_id)
        client.post("/api/v1/devices/me/presence", headers=headers(admin), json={"session_state": "unlocked"})
        client.post(f"/api/v1/notifications/{own['id']}/ack", headers=headers(admin), json={"reason": "Remote private text"})
        event = ws.receive_json()
        assert event["event_type"] == "notification.acknowledged" and event["notification_id"] == own["id"]
        assert event["ack_by_device_id"] is None and event["reason"] is None
        sentinel = post_notification(client, guest, "Sentinel")
        assert ws.receive_json()["notification"]["id"] == sentinel["id"]
    all_events = client.get("/api/v1/events", headers=auth).json()["events"]
    assert len(all_events) == 3
    assert all_events[1]["ack_by_device_id"] is None
    assert client.post(f"/api/v1/notifications/{sentinel['id']}/ack", headers=auth, json={}).status_code == 200


@pytest.mark.parametrize("event_name", ["PostToolUse", "Stop"])
def test_guest_hooks_cannot_resolve_other_devices_sessions(system, event_name):
    client, _, admin, _ = system
    guest = invite(client, admin, role="guest")
    base = {"session_id": "same-session", "tool_name": "Bash", "tool_input": {"command": "echo test"}, "cwd": "C:/test"}
    notification = client.post("/api/v1/hooks/claude", headers=headers(admin), json={
        **base, "hook_event_name": "PermissionRequest", "message": "Allow command?",
    }).json()
    assert notification is not None
    assert client.post("/api/v1/hooks/claude", headers=headers(guest), json={**base, "hook_event_name": event_name}).status_code == 200
    active = client.get("/api/v1/notifications", headers=headers(admin)).json()
    assert any(n["id"] == notification["id"] for n in active)
    client.post("/api/v1/hooks/claude", headers=headers(admin), json={**base, "hook_event_name": event_name})
    assert all(n["id"] != notification["id"] for n in client.get("/api/v1/notifications", headers=headers(admin)).json())


@pytest.mark.parametrize("kind", ["delivery", "terminal"])
def test_guest_hook_dedupe_cannot_read_or_modify_another_origin(system, kind):
    client, _, admin, _ = system
    guest = invite(client, admin, role="guest")
    payload = {"session_id": "collision", "hook_event_name": "StopFailure", "message": "Private admin text",
               "turn_id": "same-turn"} if kind == "terminal" else {
                   "session_id": "collision", "event_type": "completed", "message": "Private admin text",
                   "metadata": {"delivery_id": "same-id"},
               }
    first = client.post("/api/v1/hooks/codex", headers=headers(admin), json=payload).json()
    payload["message"] = "Guest text"
    second = client.post("/api/v1/hooks/codex", headers=headers(guest), json=payload).json()
    assert second["id"] != first["id"] and second["origin_device_id"] == guest["device"]["id"]
    assert second["body"] == "Guest text"
    retry = client.post("/api/v1/hooks/codex", headers=headers(guest), json=payload).json()
    assert retry["id"] == second["id"]
    listed = client.get("/api/v1/notifications", headers=headers(admin)).json()
    assert next(n for n in listed if n["id"] == first["id"])["body"] == "Private admin text"


def test_role_changes_apply_to_existing_credentials_sockets_and_stale_device_objects(system):
    client, storage, admin, member = system
    path = "/api/v1/devices/" + member["device"]["id"]
    post_notification(client, admin, "Before demotion")
    stale = storage.authenticate(member["access_token"])
    with client.websocket_connect("/api/v1/ws", headers=headers(member)) as ws:
        assert client.patch(path, headers=headers(admin), json={"role": "guest"}).status_code == 200
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 1012
    assert storage.events_after(None, stale) == []
    assert client.get("/api/v1/notifications", headers=headers(member)).json() == []
    with client.websocket_connect("/api/v1/ws", headers=headers(member)) as ws:
        post_notification(client, admin, "Hidden after demotion")
        own = post_notification(client, member)
        assert ws.receive_json()["notification"]["id"] == own["id"]
    assert client.patch(path, headers=headers(admin), json={"role": "member"}).status_code == 200
    assert len(client.get("/api/v1/notifications", headers=headers(member)).json()) == 3


def test_last_admin_guest_demotion_and_invitation_revocation(system):
    client, storage, admin, member = system
    assert client.patch("/api/v1/devices/" + admin["device"]["id"], headers=headers(admin),
                        json={"role": "guest"}).status_code == 409
    path = "/api/v1/devices/" + member["device"]["id"]
    client.patch(path, headers=headers(admin), json={"role": "admin"})
    code = client.post("/api/v1/devices/pair/issue", headers=headers(member)).json()["code"]
    client.patch(path, headers=headers(admin), json={"role": "guest"})
    assert client.post("/api/v1/devices/pair/consume", json={
        "code": code, "name": "Too late", "platform": "android",
    }).status_code == 401
