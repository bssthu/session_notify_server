from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import DevicePlatform, DeviceRole
from app.storage import LastAdministratorError, Storage


def headers(device):
    return {"Authorization": "Bearer " + device["access_token"]}


def invite(client, admin, *, role=None, platform="android"):
    options = {} if role is None else {"json": {"role": role}}
    issued = client.post("/api/v1/devices/pair/issue", headers=headers(admin), **options)
    assert issued.status_code == 200, issued.text
    joined = client.post("/api/v1/devices/pair/consume", json={
        "code": issued.json()["code"], "name": "New device", "platform": platform,
    })
    assert joined.status_code == 200, joined.text
    return joined.json()


@pytest.fixture
def system(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "strict")
    app = create_app(tmp_path / "roles.db")
    with TestClient(app) as client:
        code, _ = app.state.storage.issue_bootstrap_code()
        admin = client.post("/api/v1/devices/pair/consume", json={
            "code": code, "name": "First admin", "platform": "windows",
        }).json()
        member = invite(client, admin)
        yield client, app.state.storage, admin, member


def test_first_device_admin_and_invitations_default_to_member(system):
    client, _, admin, member = system
    assert admin["device"]["role"] == "admin"
    assert member["device"]["role"] == "member"
    second_admin = invite(client, admin, role="admin", platform="android")
    assert second_admin["device"]["role"] == "admin"
    assert invite(client, second_admin, platform="windows")["device"]["role"] == "member"


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/v1/devices/pair/issue", {}),
    ("POST", "/api/v1/devices/pair/issue", {"role": "admin"}),
    ("PATCH", "/api/v1/devices/{admin}", {"name": "Hijacked"}),
    ("PATCH", "/api/v1/devices/{admin}", {"notifications_enabled": False}),
    ("PATCH", "/api/v1/devices/{admin}", {"role": "member"}),
    ("PATCH", "/api/v1/devices/{member}", {"role": "admin"}),
    ("DELETE", "/api/v1/devices/{admin}", None),
])
def test_members_cannot_invite_or_change_others_even_with_direct_http(system, method, path, body):
    client, _, admin, member = system
    path = path.format(admin=admin["device"]["id"], member=member["device"]["id"])
    response = client.request(method, path, headers=headers(member), json=body)
    assert response.status_code == 403, response.text
    devices = client.get("/api/v1/devices", headers=headers(member)).json()
    assert [(d["name"], d["role"], d["notifications_enabled"]) for d in devices] == [
        ("First admin", "admin", True), ("New device", "member", True),
    ]


def test_members_keep_self_management_and_notification_delivery(system):
    client, _, admin, member = system
    path = "/api/v1/devices/" + member["device"]["id"]
    renamed = client.patch(path, headers=headers(member), json={"name": "My phone"})
    assert renamed.status_code == 200
    assert renamed.json()["role"] == "member"
    for enabled in (False, True):
        assert client.patch(path, headers=headers(member), json={"notifications_enabled": enabled}).status_code == 200
    with client.websocket_connect("/api/v1/ws", headers=headers(member)) as websocket:
        created = client.post("/api/v1/notifications", headers=headers(admin), json={
            "source": "manual", "session_id": "role-test", "title": "Visible", "body": "For members too",
        })
        assert created.status_code == 200
        event = websocket.receive_json()
        assert event["event_type"] == "notification.created"
        assert event["notification"]["body"] == "For members too"
    listed = client.get("/api/v1/notifications", headers=headers(member))
    assert listed.status_code == 200 and len(listed.json()) == 1
    assert client.delete(path, headers=headers(member)).status_code == 200
    assert client.get("/api/v1/devices", headers=headers(member)).status_code == 401


def test_roles_cannot_be_supplied_when_binding_or_consuming(system, monkeypatch):
    client, _, admin, _ = system
    code = client.post("/api/v1/devices/pair/issue", headers=headers(admin)).json()["code"]
    payload = {"name": "Attacker", "platform": "android", "role": "admin"}
    assert client.post("/api/v1/devices/pair/consume", json={**payload, "code": code}).status_code == 422
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "easy")
    assert client.post("/api/v1/devices/bind", json=payload).status_code == 422
    assert client.post("/api/v1/devices/pair/consume", json={
        "name": "Valid", "platform": "android", "code": code,
    }).json()["device"]["role"] == "member"


def test_promotion_demotion_rechecks_existing_tokens_and_cancels_invitations(system):
    client, storage, admin, member = system
    path = "/api/v1/devices/" + member["device"]["id"]
    assert client.patch(path, headers=headers(admin), json={"role": "admin"}).json()["role"] == "admin"
    stale_admin = storage.authenticate(member["access_token"])
    code = client.post("/api/v1/devices/pair/issue", headers=headers(member), json={"role": "admin"}).json()["code"]
    assert client.patch(path, headers=headers(admin), json={"role": "member"}).status_code == 200
    assert client.post("/api/v1/devices/pair/issue", headers=headers(member)).status_code == 403
    assert client.post("/api/v1/devices/pair/status", headers=headers(member), json={"code": code}).status_code == 403
    assert client.post("/api/v1/devices/pair/consume", json={
        "code": code, "name": "Too late", "platform": "windows",
    }).status_code == 401
    with pytest.raises(PermissionError):
        storage.issue_pair_code(stale_admin)
    with pytest.raises(PermissionError):
        storage.update_device(admin["device"]["id"], name="Forbidden", actor_id=stale_admin.id)
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": member["refresh_token"]}).json()
    assert refreshed["device"]["role"] == "member"
    rebound = client.post("/api/v1/devices/bind", json={
        "name": "Rebound", "platform": "windows", "refresh_token": member["refresh_token"],
    }).json()
    assert rebound["device"]["role"] == "member"
    assert client.post("/api/v1/devices/pair/issue", headers=headers(rebound)).status_code == 403


def test_last_admin_cannot_be_demoted_or_revoked(system):
    client, _, admin, member = system
    path = "/api/v1/devices/" + admin["device"]["id"]
    assert client.patch(path, headers=headers(admin), json={"role": "member"}).status_code == 409
    assert client.delete(path, headers=headers(admin)).status_code == 409
    assert client.patch("/api/v1/devices/" + member["device"]["id"],
                        headers=headers(admin), json={"role": "admin"}).status_code == 200
    assert client.delete(path, headers=headers(admin)).status_code == 200


def test_legacy_migration_preserves_all_existing_admins_once(tmp_path):
    path = tmp_path / "legacy.db"
    storage = Storage(path)
    admin = storage.bind_device("Older", DevicePlatform.windows)
    member = storage.bind_device("Newer", DevicePlatform.android)
    legacy_invite, _ = storage.issue_pair_code(admin.device)
    storage.close()
    with sqlite3.connect(path) as database:
        database.execute("ALTER TABLE devices DROP COLUMN role")
        database.execute("ALTER TABLE pair_codes DROP COLUMN role")
    storage = Storage(path)
    assert [d.role for d in storage.list_devices()] == [DeviceRole.admin, DeviceRole.admin]
    joined, _ = storage.consume_pair_code(legacy_invite, "Invited", DevicePlatform.android)
    assert joined.device.role == DeviceRole.member
    storage.update_device(member.device.id, role=DeviceRole.member, actor_id=admin.device.id)
    storage.close()
    storage = Storage(path)
    assert storage.authenticate(member.access_token).role == DeviceRole.member
    storage.close()


def test_concurrent_admin_demotion_preserves_one_admin(tmp_path):
    path = tmp_path / "concurrent.db"
    first_store = Storage(path)
    first = first_store.bind_device("First", DevicePlatform.windows)
    second = first_store.bind_device("Second", DevicePlatform.android)
    first_store.update_device(second.device.id, role=DeviceRole.admin, actor_id=first.device.id)
    second_store = Storage(path)
    def demote(args):
        storage, device_id = args
        try:
            storage.update_device(device_id, role=DeviceRole.member, actor_id=device_id)
            return "demoted"
        except LastAdministratorError:
            return "protected"
    with ThreadPoolExecutor(2) as executor:
        outcomes = list(executor.map(demote, [(first_store, first.device.id), (second_store, second.device.id)]))
    assert sorted(outcomes) == ["demoted", "protected"]
    assert sum(d.role == DeviceRole.admin for d in first_store.list_devices()) == 1
    first_store.close()
    second_store.close()
