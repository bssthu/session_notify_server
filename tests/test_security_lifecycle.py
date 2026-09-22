"""Isolated lifecycle regressions. No listening server or external requests."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect

from app.hub import WebSocketHub
from app.main import create_app
from app.schemas import DevicePlatform, EventType, SyncEvent, new_id, utc_now
from app.security import sha256_text
from app.storage import Storage, _dt


def test_bootstrap_and_revoke_pair_lifecycle(tmp_path):
    storage = Storage(tmp_path / "state.db")
    try:
        code, _ = storage.issue_bootstrap_code()
        host, _ = storage.consume_pair_code(code, "Desktop", DevicePlatform.windows)
        assert storage.consume_pair_code(code, "Desktop", DevicePlatform.windows) is None
        with pytest.raises(ValueError):
            storage.issue_bootstrap_code()
        invitation, _ = storage.issue_pair_code(host.device)
        storage.revoke_device(host.device.id)
        assert storage.consume_pair_code(invitation, "Phone", DevicePlatform.android) is None
        with pytest.raises(ValueError):
            storage.issue_pair_code(host.device)
        replacement, _ = storage.issue_bootstrap_code()
        storage.revoke_all_devices()
        assert storage.consume_pair_code(replacement, "Desktop", DevicePlatform.windows) is None
        fresh, _ = storage.issue_bootstrap_code()
        assert storage.consume_pair_code(fresh, "Desktop", DevicePlatform.windows) is not None
    finally:
        storage.close()


def test_pair_consumption_commits_once_across_storage_connections(tmp_path):
    stores = [Storage(tmp_path / "state.db") for _ in range(2)]
    try:
        code, _ = stores[0].issue_bootstrap_code()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda store: store.consume_pair_code(code, "Desktop", DevicePlatform.windows), stores))
        assert sum(result is not None for result in results) == 1
        assert len(stores[0].list_devices()) == 1
    finally:
        for store in stores:
            store.close()


def test_strict_initialization_and_configuration_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "strict")
    with TestClient(create_app(tmp_path / "state.db")) as client:
        result = client.post("/api/v1/devices/bind", json={"name": "Desktop", "platform": "windows"})
        assert result.status_code == 401
        assert client.app.state.storage.list_devices() == []
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "strcit")
    with pytest.raises(ValueError, match="PAIR_MODE"):
        create_app(tmp_path / "invalid.db")


class Socket:
    def __init__(self):
        self.payloads = []
        self.close_code = None

    async def accept(self):
        pass

    async def send_json(self, value):
        self.payloads.append(value)

    async def close(self, code):
        self.close_code = code


@pytest.mark.parametrize("change", ["expire", "refresh", "revoke"])
def test_idle_websocket_closes_when_its_authorization_ends(tmp_path, change):
    app = create_app(tmp_path / "state.db")
    storage = app.state.storage
    auth = storage.bind_device("Desktop", DevicePlatform.windows)
    with TestClient(app) as client:
        with client.websocket_connect("/api/v1/ws", headers={"Authorization": f"Bearer {auth.access_token}"}) as socket:
            if change == "expire":
                with storage._conn:
                    storage._conn.execute("UPDATE devices SET access_expires_at = ?", (_dt(utc_now() - timedelta(seconds=1)),))
            elif change == "refresh":
                storage.refresh_access_token(auth.refresh_token)
            else:
                storage.revoke_device(auth.device.id)
            with pytest.raises(WebSocketDisconnect) as closed:
                socket.receive_json()
            assert closed.value.code == 1008


def test_local_bootstrap_command_produces_a_usable_code(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path

    db = tmp_path / "state.db"
    script = Path(__file__).resolve().parents[1] / "scripts" / "issue_bootstrap_code.py"
    result = subprocess.run([sys.executable, str(script), "--db", str(db), "--json"],
                            capture_output=True, encoding="utf-8", check=True)
    code = json.loads(result.stdout)["code"]
    storage = Storage(db)
    try:
        assert len(code) == 32
        assert storage.consume_pair_code(code, "Desktop", DevicePlatform.windows) is not None
    finally:
        storage.close()


@pytest.mark.parametrize("change", ["expire", "refresh", "revoke"])
def test_websocket_authorization_follows_credential_lifecycle(tmp_path, change):
    storage = Storage(tmp_path / "state.db")
    try:
        auth = storage.bind_device("Desktop", DevicePlatform.windows)
        token_hash = sha256_text(auth.access_token)
        event = SyncEvent(event_id=new_id(), event_type=EventType.notification_expired,
                          created_at=utc_now(), notification_id="finished")

        async def scenario():
            socket = Socket()
            hub = WebSocketHub()
            await hub.connect(socket, auth.device.id, lambda: storage.access_token_is_valid(token_hash))
            await hub.broadcast(event, storage.should_deliver_event_to_device)
            assert len(socket.payloads) == 1
            if change == "expire":
                with storage._conn:
                    storage._conn.execute("UPDATE devices SET access_expires_at = ?", (_dt(utc_now() - timedelta(seconds=1)),))
            elif change == "refresh":
                storage.refresh_access_token(auth.refresh_token)
            else:
                storage.revoke_device(auth.device.id)
                assert not storage.should_deliver_event_to_device(event, auth.device.id)
            await hub.broadcast(event, storage.should_deliver_event_to_device)
            assert len(socket.payloads) == 1
            assert socket.close_code == 1008
            assert not hub._connections

        asyncio.run(scenario())
    finally:
        storage.close()
