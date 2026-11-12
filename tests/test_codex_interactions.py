from fastapi.testclient import TestClient

from app.main import create_app


def test_interaction_is_shared_with_phone_and_resolution_is_synchronized(tmp_path):
    with TestClient(create_app(tmp_path / "interactions.db")) as client:
        windows = client.post("/api/v1/devices/bind", json={"name": "PC", "platform": "windows"}).json()
        phone = client.post("/api/v1/devices/bind", json={"name": "Phone", "platform": "android"}).json()
        wh = {"Authorization": "Bearer " + windows["access_token"]}
        ph = {"Authorization": "Bearer " + phone["access_token"]}
        payload = {
            "event_type": "interaction_waiting", "hook_event_name": "CodexInteraction",
            "hook_status": "waiting", "notification_type": "codex_interaction",
            "notification_level": "important", "notification_title": "Codex 等待交互确认",
            "session_id": "cli", "message": "Allow Codex to use Google Chrome?",
            "metadata": {"delivery_id": "episode-1", "interaction_id": "episode-1",
                         "event_family": "codex_interaction", "ingest_source": "app_server"},
        }
        client.post("/api/v1/devices/me/presence", headers=wh, json={
            "session_state": "locked", "suppress_codex_permission_requests": True,
        }).raise_for_status()
        created = client.post("/api/v1/hooks/codex", headers=wh, json=payload)
        created.raise_for_status()
        notification = created.json()
        assert notification["level"] == "important"
        assert not notification["metadata"].get("local_only")
        replay = client.post("/api/v1/hooks/codex", headers=wh, json=payload).json()
        assert replay["id"] == notification["id"]
        for headers in (wh, ph):
            active = client.get("/api/v1/notifications", headers=headers).json()
            assert [n["id"] for n in active] == [notification["id"]]
            events = client.get("/api/v1/events", headers=headers).json()["events"]
            assert sum(e["event_type"] == "notification.created" for e in events) == 1
        client.post(f'/api/v1/notifications/{notification["id"]}/ack', headers=wh,
                    json={"reason": "interaction_resolved"}).raise_for_status()
        assert client.get("/api/v1/notifications", headers=ph).json() == []
        assert any(e.get("notification_id") == notification["id"] and e.get("reason") == "interaction_resolved"
                   for e in client.get("/api/v1/events", headers=ph).json()["events"])
        # Lost-response replay cannot revive an acknowledged episode.
        assert client.post("/api/v1/hooks/codex", headers=wh, json=payload).json()["status"] == "acknowledged"
        client.patch(f'/api/v1/devices/{windows["device"]["id"]}', headers=wh,
                     json={"silent_notifications": True}).raise_for_status()
        payload["metadata"]["delivery_id"] = "silent-episode"
        assert client.post("/api/v1/hooks/codex", headers=wh, json=payload).json()["status"] == "acknowledged"
        assert client.get("/api/v1/notifications", headers=ph).json() == []
        client.patch(f'/api/v1/devices/{windows["device"]["id"]}', headers=wh,
                     json={"hook_notifications_enabled": False}).raise_for_status()
        payload["metadata"]["delivery_id"] = "disabled-episode"
        assert client.post("/api/v1/hooks/codex", headers=wh, json=payload).json() is None
