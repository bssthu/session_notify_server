"""Refresh lifetime policy, recovery, last-admin protection and SQLite races.

All transport tests use in-process TestClient. No real service or credentials.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect

from app.main import create_app
from app.schemas import DevicePlatform, DeviceRole
from app.security import sha256_text
from app.storage import AuthenticationError, LastAdministratorError, LastAdministratorExpiryError, Storage, _dt


@pytest.fixture
def clock(monkeypatch):
    class Clock:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)

        def advance(self, **kwargs):
            self.now += timedelta(**kwargs)
    clock = Clock()
    monkeypatch.setattr("app.storage.utc_now", lambda: clock.now)
    monkeypatch.setattr("app.main.utc_now", lambda: clock.now)
    return clock


@pytest.fixture
def system(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "strict")
    app = create_app(tmp_path / "expiry.db")
    with TestClient(app) as client:
        store = app.state.storage
        code, _ = store.issue_bootstrap_code()
        first = client.post("/api/v1/devices/pair/consume", json={
            "code": code, "name": "Admin", "platform": "windows",
        }).json()
        yield client, store, first


def headers(auth):
    return {"Authorization": "Bearer " + auth["access_token"]}


def invite(client, admin, **policy):
    issued = client.post("/api/v1/devices/pair/issue", headers=headers(admin), json=policy)
    assert issued.status_code == 200, issued.text
    joined = client.post("/api/v1/devices/pair/consume", json={
        "code": issued.json()["code"], "name": "Invited", "platform": "android",
    })
    assert joined.status_code == 200, joined.text
    return joined.json()


def patch(client, admin, target, **policy):
    return client.patch("/api/v1/devices/" + target["device"]["id"], headers=headers(admin), json=policy)


def assert_metadata(auth):
    assert auth["access_expires_at"] == auth["device"]["access_expires_at"]
    assert auth["refresh_expires_at"] == auth["device"]["refresh_expires_at"]
    assert auth["server_time"]
    if auth["refresh_expires_at"]:
        assert datetime.fromisoformat(auth["access_expires_at"]) <= datetime.fromisoformat(auth["refresh_expires_at"])


def test_first_admin_permanent_defaults_and_response_metadata(clock, system):
    client, store, admin = system
    assert_metadata(admin)
    assert admin["refresh_expires_at"] is None
    member = invite(client, admin)
    assert_metadata(member)
    assert datetime.fromisoformat(member["refresh_expires_at"]) == clock.now + timedelta(days=90)
    listed = client.get("/api/v1/devices", headers=headers(admin)).json()
    assert listed[0]["refresh_expires_at"] is None
    assert listed[1]["refresh_expires_at"] == member["refresh_expires_at"]
    assert listed[1]["access_expires_at"] == member["access_expires_at"]
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": member["refresh_token"]}).json()
    assert_metadata(refreshed)
    assert refreshed["refresh_expires_at"] == member["refresh_expires_at"]


@pytest.mark.parametrize("policy", [
    {"refresh_ttl_days": 7}, {"refresh_ttl_days": None},
    {"refresh_expires_at": None}, {"refresh_expires_at": "2030-01-01T00:00:20Z"},
])
def test_pair_policy_is_authoritative_and_access_capped(clock, system, policy):
    client, _, admin = system
    member = invite(client, admin, **policy)
    assert_metadata(member)
    if "refresh_ttl_days" in policy and policy["refresh_ttl_days"]:
        assert datetime.fromisoformat(member["refresh_expires_at"]) == clock.now + timedelta(days=7)
    elif policy.get("refresh_expires_at"):
        assert datetime.fromisoformat(member["refresh_expires_at"]) == clock.now + timedelta(seconds=20)
        assert member["refresh_expires_at"] == member["access_expires_at"]
    else:
        assert member["refresh_expires_at"] is None


@pytest.mark.parametrize("policy", [
    {"refresh_ttl_days": 0}, {"refresh_ttl_days": -1}, {"refresh_ttl_days": 1.5},
    {"refresh_ttl_days": True}, {"refresh_ttl_days": "7"}, {"refresh_ttl_days": 36501},
    {"refresh_expires_at": "2030-01-01T00:01:00"},
    {"refresh_expires_at": "2030-01-01T00:00:00Z"},
    {"refresh_expires_at": "2029-12-31T23:59:59Z"},
    {"refresh_ttl_days": None, "refresh_expires_at": None},
    {"refresh_ttl_days": 7, "refresh_expires_at": None},
])
def test_invalid_policies_rejected(clock, system, policy):
    client, _, admin = system
    member = invite(client, admin)
    assert client.post("/api/v1/devices/pair/issue", headers=headers(admin), json=policy).status_code == 422
    assert patch(client, admin, member, **policy).status_code == 422


@pytest.mark.parametrize("role", ["member", "guest"])
def test_non_admin_cannot_change_even_own_expiry(clock, system, role):
    client, _, admin = system
    member = invite(client, admin, role=role)
    for policy in ({"refresh_ttl_days": 7}, {"refresh_expires_at": None}):
        assert patch(client, member, member, **policy).status_code == 403
        assert patch(client, member, admin, **policy).status_code == 403
        assert client.post("/api/v1/devices/pair/issue", headers=headers(member), json=policy).status_code == 403
    assert patch(client, member, member, name="Own name").status_code == 200


def test_omitted_patch_preserves_and_admin_can_shorten_extend_make_permanent(clock, system):
    client, _, admin = system
    member = invite(client, admin)
    renamed = patch(client, admin, member, name="Renamed").json()
    assert renamed["refresh_expires_at"] == member["refresh_expires_at"]
    shortened = patch(client, admin, member, refresh_expires_at=_dt(clock.now + timedelta(seconds=15))).json()
    assert shortened["access_expires_at"] == shortened["refresh_expires_at"]
    extended = patch(client, admin, member, refresh_ttl_days=120).json()
    assert datetime.fromisoformat(extended["refresh_expires_at"]) == clock.now + timedelta(days=120)
    # Extending refresh must not resurrect or prolong an already-issued access token.
    assert extended["access_expires_at"] == shortened["access_expires_at"]
    permanent = patch(client, admin, member, refresh_expires_at=None).json()
    assert permanent["refresh_expires_at"] is None
    assert permanent["access_expires_at"] == shortened["access_expires_at"]


def test_expired_device_waits_for_admin_extension_then_same_refresh_recovers(clock, system):
    client, store, admin = system
    member = invite(client, admin, refresh_expires_at=_dt(clock.now + timedelta(seconds=10)))
    clock.advance(seconds=10)
    for url, data in [
        ("/api/v1/auth/refresh", {"refresh_token": member["refresh_token"]}),
        ("/api/v1/devices/bind", {"refresh_token": member["refresh_token"], "name": "Again", "platform": "android"}),
    ]:
        failure = client.post(url, json=data)
        assert failure.status_code == 401
        assert failure.json()["detail"]["code"] == "refresh_token_expired"
        assert failure.json()["detail"]["server_time"]
    assert client.get("/api/v1/devices", headers=headers(member)).json()["detail"]["code"] == "refresh_token_expired"
    assert patch(client, member, member, refresh_expires_at=None).status_code == 401
    with pytest.raises(WebSocketDisconnect) as rejected:
        with client.websocket_connect("/api/v1/ws", headers=headers(member)):
            pass
    assert rejected.value.code == 1008
    assert rejected.value.reason == "refresh_token_expired"
    # Admin still sees expired target and may extend it without rotating refresh.
    assert any(d["id"] == member["device"]["id"] for d in client.get("/api/v1/devices", headers=headers(admin)).json())
    assert patch(client, admin, member, refresh_ttl_days=7).status_code == 200
    resumed = client.post("/api/v1/auth/refresh", json={"refresh_token": member["refresh_token"]})
    assert resumed.status_code == 200
    assert_metadata(resumed.json())
    assert client.get("/api/v1/devices", headers=headers(resumed.json())).status_code == 200
    assert client.delete("/api/v1/devices/" + member["device"]["id"], headers=headers(admin)).status_code == 200
    assert patch(client, admin, member, refresh_ttl_days=7).status_code == 404
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": member["refresh_token"]}).json()["detail"]["code"] == "device_revoked"
    assert client.get("/api/v1/devices", headers=headers(resumed.json())).json()["detail"]["code"] == "device_revoked"


def test_typed_access_and_invalid_errors(clock, system):
    client, _, admin = system
    member = invite(client, admin)
    clock.advance(hours=2)
    expired = client.get("/api/v1/devices", headers=headers(member))
    assert expired.status_code == 401 and expired.json()["detail"]["code"] == "access_token_expired"
    for response in (client.get("/api/v1/devices"), client.get("/api/v1/devices", headers={"Authorization": "Bearer bad"}),
                     client.post("/api/v1/auth/refresh", json={"refresh_token": "bad"})):
        assert response.status_code == 401 and response.json()["detail"]["code"] == "invalid_token"
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": member["refresh_token"]})
    assert refreshed.status_code == 200


def test_rebind_preserves_deadline_rotates_tokens_and_rejects_policy(clock, system):
    client, _, admin = system
    member = invite(client, admin, refresh_expires_at=_dt(clock.now + timedelta(seconds=30)))
    clock.advance(seconds=10)
    body = {"refresh_token": member["refresh_token"], "name": "Rebound", "platform": "windows"}
    assert client.post("/api/v1/devices/bind", json={**body, "refresh_ttl_days": 90}).status_code == 422
    rebound = client.post("/api/v1/devices/bind", json=body).json()
    assert_metadata(rebound)
    assert rebound["device"]["id"] == member["device"]["id"]
    assert rebound["refresh_expires_at"] == member["refresh_expires_at"]
    assert rebound["access_expires_at"] == member["access_expires_at"]
    assert rebound["refresh_token"] != member["refresh_token"]
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": member["refresh_token"]}).json()["detail"]["code"] == "invalid_token"


def test_pair_relative_policy_starts_on_consume_absolute_can_expire(clock, system):
    client, _, admin = system
    issued = client.post("/api/v1/devices/pair/issue", headers=headers(admin), json={"refresh_ttl_days": 7}).json()
    clock.advance(seconds=60)
    member = client.post("/api/v1/devices/pair/consume", json={"code": issued["code"], "name": "Delayed", "platform": "android"}).json()
    assert datetime.fromisoformat(member["refresh_expires_at"]) == clock.now + timedelta(days=7)
    absolute = client.post("/api/v1/devices/pair/issue", headers=headers(admin), json={"refresh_expires_at": _dt(clock.now + timedelta(seconds=10))}).json()
    clock.advance(seconds=10)
    assert client.post("/api/v1/devices/pair/consume", json={"code": absolute["code"], "name": "Late", "platform": "android"}).status_code == 401


def test_sole_admin_cannot_be_given_finite_expiry(clock, system):
    client, _, admin = system
    response = patch(client, admin, admin, refresh_ttl_days=7)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "last_admin_must_be_permanent"
    assert patch(client, admin, admin, refresh_ttl_days=None).json()["refresh_expires_at"] is None


@pytest.mark.parametrize("operation", ["demote", "revoke"])
def test_removing_an_admin_makes_remaining_admin_permanent(clock, tmp_path, operation):
    store = Storage(tmp_path / "state.db")
    try:
        a = store.bind_device("First", DevicePlatform.windows)
        b = store.bind_device("Second", DevicePlatform.android)
        store.update_device(b.device.id, role=DeviceRole.admin, actor_id=a.device.id)
        assert store.authenticate(b.access_token).refresh_expires_at is not None
        if operation == "demote":
            store.update_device(a.device.id, role=DeviceRole.member, actor_id=a.device.id)
        else:
            store.revoke_device(a.device.id, actor_id=a.device.id)
        assert store.authenticate(b.access_token).refresh_expires_at is None
    finally:
        store.close()


@pytest.mark.parametrize("equal", [False, True])
def test_expiry_transition_preserves_deterministic_last_survivor_even_after_idle(clock, tmp_path, equal):
    path = tmp_path / "state.db"
    store = Storage(path)
    try:
        a = store.bind_device("First", DevicePlatform.windows)
        clock.advance(seconds=1)
        b = store.bind_device("Second", DevicePlatform.android)
        store.update_device(b.device.id, role=DeviceRole.admin, actor_id=a.device.id)
        first_deadline = clock.now + timedelta(minutes=1)
        last_deadline = first_deadline if equal else first_deadline + timedelta(minutes=1)
        store.update_device(a.device.id, refresh_expires_at=first_deadline, actor_id=a.device.id)
        store.update_device(b.device.id, refresh_expires_at=last_deadline, actor_id=a.device.id)
        clock.advance(minutes=5)  # No sweep at either boundary; both dates are now past.
        assert store.refresh_access_token(a.refresh_token) is None
        resumed = store.refresh_access_token(b.refresh_token)
        assert resumed is not None and resumed.refresh_expires_at is None
        assert store.authenticate(a.access_token) is None
        assert store.authenticate(resumed.access_token).role == DeviceRole.admin
        assert store._conn.execute("SELECT refresh_expires_at FROM devices WHERE id = ?", (a.device.id,)).fetchone()[0] == _dt(first_deadline)
        # Surviving admin cannot be demoted/revoked with an expired-only alternative.
        with pytest.raises(LastAdministratorError):
            store.revoke_device(b.device.id, actor_id=b.device.id)
        with pytest.raises(LastAdministratorError):
            store.update_device(b.device.id, role=DeviceRole.member, actor_id=b.device.id)
    finally:
        store.close()


def test_last_survivor_equal_created_and_deadline_uses_id(clock, tmp_path):
    store = Storage(tmp_path / "state.db")
    try:
        a = store.bind_device("First", DevicePlatform.windows)
        b = store.bind_device("Second", DevicePlatform.android)
        store.update_device(b.device.id, role=DeviceRole.admin, actor_id=a.device.id)
        expiry = clock.now + timedelta(seconds=10)
        store.update_device(a.device.id, refresh_expires_at=expiry, actor_id=a.device.id)
        store.update_device(b.device.id, refresh_expires_at=expiry, actor_id=a.device.id)
        clock.advance(seconds=10)
        store.enforce_admin_expiry_invariant()
        winner = max(a.device.id, b.device.id)
        assert {d.id for d in store.list_devices() if d.refresh_expires_at is None} == {winner}
    finally:
        store.close()


def test_expired_pair_issuer_does_not_authorize_consumption(clock, system):
    client, _, admin = system
    other = invite(client, admin, role="admin", refresh_expires_at=_dt(clock.now + timedelta(seconds=10)))
    issued = client.post("/api/v1/devices/pair/issue", headers=headers(other)).json()
    clock.advance(seconds=10)
    assert client.post("/api/v1/devices/pair/consume", json={"code": issued["code"], "name": "Late", "platform": "android"}).status_code == 401


def test_migration_repairs_sole_admin_caps_access_and_keeps_legacy_permanent(clock, tmp_path):
    path = tmp_path / "state.db"
    store = Storage(path)
    admin = store.bind_device("First", DevicePlatform.windows)
    member = store.bind_device("Legacy permanent", DevicePlatform.android)
    finite = store.bind_device("Finite legacy access", DevicePlatform.android)
    store.close()
    with sqlite3.connect(path) as db:
        db.execute("UPDATE devices SET refresh_expires_at = ? WHERE id = ?", (_dt(clock.now - timedelta(days=1)), admin.device.id))
        db.execute("UPDATE devices SET refresh_expires_at = NULL WHERE id = ?", (member.device.id,))
        db.execute("UPDATE devices SET access_expires_at = NULL WHERE id = ?", (finite.device.id,))
        db.execute("ALTER TABLE pair_codes DROP COLUMN refresh_ttl_days")
        db.execute("ALTER TABLE pair_codes DROP COLUMN refresh_expires_at")
    store = Storage(path)
    try:
        by_id = {d.id: d for d in store.list_devices()}
        assert by_id[admin.device.id].refresh_expires_at is None
        assert by_id[member.device.id].refresh_expires_at is None
        assert by_id[finite.device.id].access_expires_at == by_id[finite.device.id].refresh_expires_at
        assert store.refresh_access_token(admin.refresh_token).refresh_expires_at is None
    finally:
        store.close()


def test_refresh_expiry_blocks_legacy_unbounded_access_and_idle_socket(clock, system):
    client, store, admin = system
    member = invite(client, admin, refresh_expires_at=_dt(clock.now + timedelta(seconds=10)))
    with store._conn:
        store._conn.execute("UPDATE devices SET access_expires_at = NULL WHERE id = ?", (member["device"]["id"],))
    with client.websocket_connect("/api/v1/ws", headers=headers(member)) as socket:
        clock.advance(seconds=10)
        assert not store.access_token_is_valid(sha256_text(member["access_token"]))
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == 1008
        assert closed.value.reason == "refresh_token_expired"


@pytest.mark.parametrize("operation", ["refresh", "rebind"])
def test_cross_connection_renewal_and_shortening_are_serialized(clock, tmp_path, operation):
    path = tmp_path / "race.db"
    stores = [Storage(path), Storage(path)]
    try:
        admin = stores[0].bind_device("Admin", DevicePlatform.windows)
        member = stores[0].bind_device("Member", DevicePlatform.android)
        deadline = clock.now + timedelta(seconds=20)
        barrier = threading.Barrier(2)
        def shorten():
            barrier.wait()
            return stores[0].update_device(member.device.id, refresh_expires_at=deadline, actor_id=admin.device.id)
        def renew():
            barrier.wait()
            if operation == "refresh":
                return stores[1].refresh_access_token(member.refresh_token)
            return stores[1].rebind_device(member.refresh_token, "Rebound", DevicePlatform.android)
        with ThreadPoolExecutor(2) as pool:
            f1, f2 = pool.submit(shorten), pool.submit(renew)
            f1.result(); renewed = f2.result()
        final = stores[0].authenticate(renewed.access_token)
        assert final.refresh_expires_at == deadline
        assert final.access_expires_at <= deadline
        clock.advance(seconds=20)
        assert not stores[1].access_token_is_valid(sha256_text(renewed.access_token))
        assert stores[1].refresh_access_token(getattr(renewed, "refresh_token", member.refresh_token)) is None
    finally:
        for store in stores:
            store.close()


def test_cross_connection_competing_admin_expiry_changes_never_make_sole_finite(clock, tmp_path):
    path = tmp_path / "race.db"
    stores = [Storage(path), Storage(path)]
    try:
        a = stores[0].bind_device("First", DevicePlatform.windows)
        b = stores[0].bind_device("Second", DevicePlatform.android)
        stores[0].update_device(b.device.id, role=DeviceRole.admin, actor_id=a.device.id)
        barrier = threading.Barrier(2)
        def demote():
            barrier.wait()
            return stores[0].update_device(a.device.id, role=DeviceRole.member, actor_id=a.device.id)
        def finite():
            barrier.wait()
            try:
                return stores[1].update_device(b.device.id, refresh_ttl_days=7, actor_id=b.device.id)
            except LastAdministratorExpiryError:
                return None
        with ThreadPoolExecutor(2) as pool:
            f1, f2 = pool.submit(demote), pool.submit(finite)
            f1.result(); f2.result()
        admins = [d for d in stores[0].list_devices() if d.role == DeviceRole.admin]
        assert len(admins) == 1 and admins[0].refresh_expires_at is None
    finally:
        for store in stores:
            store.close()


def test_expired_windows_presence_no_longer_suppresses_mobile(clock, system):
    from app.schemas import DeviceSessionState
    client, store, admin = system
    code, _ = store.issue_pair_code(store.authenticate(admin["access_token"]), refresh_expires_at=clock.now + timedelta(seconds=10))
    windows, _ = store.consume_pair_code(code, "Windows", DevicePlatform.windows)
    store.update_device_session_state(windows.device.id, DeviceSessionState.unlocked,
        notification_pause_until=None, suppress_codex_permission_requests=False, stale_after=timedelta(seconds=90))
    assert store.device_presence_summary(timedelta(seconds=90)).any_unlocked_windows
    clock.advance(seconds=10)
    summary = store.device_presence_summary(timedelta(seconds=90))
    assert not summary.any_unlocked_windows
    assert not summary.any_unlocked_unpaused_windows
    expired = next(d for d in summary.windows_devices if d.device_id == windows.device.id)
    assert expired.reported_session_state == DeviceSessionState.unlocked
    assert expired.effective_session_state == DeviceSessionState.unknown
    with pytest.raises(AuthenticationError, match="expired"):
        store.update_device_session_state(windows.device.id, DeviceSessionState.unlocked,
            notification_pause_until=None, suppress_codex_permission_requests=False, stale_after=timedelta(seconds=90))


def test_expired_actor_cannot_use_stale_admin_snapshot(clock, tmp_path):
    store = Storage(tmp_path / "state.db")
    try:
        first = store.bind_device("Permanent", DevicePlatform.windows)
        other = store.bind_device("Other admin", DevicePlatform.android)
        store.update_device(other.device.id, role=DeviceRole.admin, refresh_expires_at=clock.now + timedelta(seconds=10), actor_id=first.device.id)
        stale = store.authenticate(other.access_token)
        clock.advance(seconds=10)
        with pytest.raises(AuthenticationError) as failure:
            store.update_device(other.device.id, refresh_ttl_days=90, actor_id=stale.id)
        assert failure.value.code == "refresh_token_expired"
        with pytest.raises(AuthenticationError):
            store.issue_pair_code(stale)
        assert store.refresh_access_token(other.refresh_token) is None
        assert store.authenticate(first.access_token).refresh_expires_at is None
    finally:
        store.close()


@pytest.mark.parametrize("operation", ["refresh", "rebind"])
def test_cross_connection_revoke_and_credential_rotation_cannot_revive(clock, tmp_path, operation):
    path = tmp_path / "race.db"
    stores = [Storage(path), Storage(path)]
    try:
        admin = stores[0].bind_device("Admin", DevicePlatform.windows)
        member = stores[0].bind_device("Member", DevicePlatform.android)
        barrier = threading.Barrier(2)
        def revoke():
            barrier.wait()
            return stores[0].revoke_device(member.device.id, actor_id=admin.device.id)
        def renew():
            barrier.wait()
            if operation == "refresh":
                return stores[1].refresh_access_token(member.refresh_token)
            return stores[1].rebind_device(member.refresh_token, "Rebound", DevicePlatform.android)
        with ThreadPoolExecutor(2) as pool:
            f1, f2 = pool.submit(revoke), pool.submit(renew)
            f1.result(); renewed = f2.result()
        if renewed:
            assert stores[0].authenticate(renewed.access_token) is None
            assert stores[0].refresh_access_token(getattr(renewed, "refresh_token", member.refresh_token)) is None
        assert stores[0].authenticate(member.access_token) is None
        assert stores[0].refresh_access_token(member.refresh_token) is None
        with pytest.raises(KeyError):
            stores[0].update_device(member.device.id, refresh_ttl_days=90, actor_id=admin.device.id)
    finally:
        for store in stores:
            store.close()


def test_concurrent_expiry_sweep_and_refresh_elect_only_one_survivor(clock, tmp_path):
    path = tmp_path / "race.db"
    stores = [Storage(path), Storage(path)]
    try:
        first = stores[0].bind_device("First", DevicePlatform.windows)
        second = stores[0].bind_device("Second", DevicePlatform.android)
        stores[0].update_device(second.device.id, role=DeviceRole.admin, actor_id=first.device.id)
        expiry = clock.now + timedelta(seconds=10)
        stores[0].update_device(first.device.id, refresh_expires_at=expiry, actor_id=first.device.id)
        stores[0].update_device(second.device.id, refresh_expires_at=expiry, actor_id=first.device.id)
        clock.advance(seconds=10)
        barrier = threading.Barrier(2)
        def refresh(args):
            store, token = args
            barrier.wait()
            return store.refresh_access_token(token)
        with ThreadPoolExecutor(2) as pool:
            outcomes = list(pool.map(refresh, [(stores[0], first.refresh_token), (stores[1], second.refresh_token)]))
        assert sum(result is not None for result in outcomes) == 1
        permanent = [d for d in stores[0].list_devices() if d.refresh_expires_at is None]
        assert len(permanent) == 1 and permanent[0].id == max(first.device.id, second.device.id)
    finally:
        for store in stores:
            store.close()


def test_admin_expiry_patch_closes_socket_before_client_reconnect(clock, system):
    client, store, admin = system
    member = invite(client, admin)
    with client.websocket_connect("/api/v1/ws", headers=headers(member)) as socket:
        response = patch(client, admin, member, refresh_expires_at=_dt(clock.now + timedelta(seconds=10)))
        assert response.status_code == 200
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
        assert closed.value.code == 1012
        assert closed.value.reason == "Device authorization changed"
    clock.advance(seconds=10)
    assert not store.access_token_is_valid(sha256_text(member["access_token"]))
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/v1/ws", headers=headers(member)):
            pass


def test_audit_records_policy_without_tokens_or_hashes(clock, system, caplog):
    client, _, admin = system
    member = invite(client, admin)
    with caplog.at_level("INFO", logger="app.storage"):
        assert patch(client, admin, member, refresh_ttl_days=7).status_code == 200
    assert "refresh expiry changed by administrator" in caplog.text
    for auth in (admin, member):
        for key in ("access_token", "refresh_token"):
            assert auth[key] not in caplog.text
            assert sha256_text(auth[key]) not in caplog.text


def test_offset_absolute_date_normalized_and_survives_server_restart(clock, tmp_path):
    path = tmp_path / "state.db"
    store = Storage(path)
    first = store.bind_device("First", DevicePlatform.windows)
    member = store.bind_device("Member", DevicePlatform.android)
    deadline = datetime(2030, 1, 2, 3, 0, tzinfo=timezone(timedelta(hours=3)))
    updated = store.update_device(member.device.id, refresh_expires_at=deadline, actor_id=first.device.id)
    assert updated.refresh_expires_at == datetime(2030, 1, 2, tzinfo=timezone.utc)
    code, _ = store.issue_pair_code(store.authenticate(first.access_token), refresh_ttl_days=None)
    store.close()
    store = Storage(path)
    try:
        assert store.authenticate(member.access_token).refresh_expires_at == updated.refresh_expires_at
        invited, _ = store.consume_pair_code(code, "Permanent after restart", DevicePlatform.android)
        assert invited.refresh_expires_at is None
    finally:
        store.close()


def test_concurrent_rebind_consumes_old_credential_once(clock, tmp_path):
    path = tmp_path / "race.db"
    stores = [Storage(path), Storage(path)]
    try:
        stores[0].bind_device("Admin", DevicePlatform.windows)
        member = stores[0].bind_device("Member", DevicePlatform.android)
        barrier = threading.Barrier(2)
        def rebind(store):
            barrier.wait()
            return store.rebind_device(member.refresh_token, "Rebound", DevicePlatform.android)
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(rebind, stores))
        winners = [result for result in results if result]
        assert len(winners) == 1
        assert winners[0].refresh_expires_at == member.refresh_expires_at
        assert stores[0].refresh_access_token(member.refresh_token) is None
        assert stores[0].refresh_access_token(winners[0].refresh_token) is not None
    finally:
        for store in stores:
            store.close()
