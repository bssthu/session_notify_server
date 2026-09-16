from __future__ import annotations

from datetime import datetime, timedelta

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


def test_recent_notifications_are_paginated_and_limited_to_requested_days(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)
    now = utc_now()
    created: list[tuple[str, str, int]] = []

    for index, age_days in enumerate((1, 2, 3, 4, 31), start=1):
        response = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json={
                "source": "codex",
                "session_id": "history",
                "title": f"History {index}",
                "body": f"Created {age_days} days ago",
            },
        )
        assert response.status_code == 200, response.text
        created.append((response.json()["id"], f"History {index}", age_days))

    storage = app.state.storage
    with storage._lock, storage._conn:
        for notification_id, _title, age_days in created:
            created_at = (now - timedelta(days=age_days)).isoformat()
            storage._conn.execute(
                "UPDATE notifications SET created_at = ?, updated_at = ? WHERE id = ?",
                (created_at, created_at, notification_id),
            )

    first = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"days": 7, "limit": 2},
    )
    assert first.status_code == 200, first.text
    first_page = first.json()
    assert [item["title"] for item in first_page["items"]] == ["History 1", "History 2"]
    assert first_page["has_more"] is True
    assert first_page["next_cursor"]
    assert first_page["requested_days"] == 7
    assert first_page["effective_days"] == 7
    assert first_page["total_count"] == 4
    assert first_page["total_pages"] == 2

    second = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"days": 7, "limit": 2, "cursor": first_page["next_cursor"]},
    )
    assert second.status_code == 200, second.text
    second_page = second.json()
    assert [item["title"] for item in second_page["items"]] == ["History 3", "History 4"]
    assert second_page["has_more"] is False
    assert second_page["next_cursor"] is None
    assert second_page["total_count"] == 4
    assert second_page["total_pages"] == 2


def test_notification_history_has_a_server_side_30_day_hard_limit(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)
    now = utc_now()
    notification_ids: dict[str, str] = {}

    for title in ("Within limit", "Outside limit"):
        response = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json={
                "source": "codex",
                "session_id": "history-limit",
                "title": title,
                "body": title,
            },
        )
        assert response.status_code == 200, response.text
        notification_ids[title] = response.json()["id"]

    storage = app.state.storage
    with storage._lock, storage._conn:
        for title, age_days in (("Within limit", 29), ("Outside limit", 31)):
            created_at = (now - timedelta(days=age_days)).isoformat()
            storage._conn.execute(
                "UPDATE notifications SET created_at = ?, updated_at = ? WHERE id = ?",
                (created_at, created_at, notification_ids[title]),
            )

    recent = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"days": 60, "limit": 100},
    )
    assert recent.status_code == 200, recent.text
    page = recent.json()
    assert page["requested_days"] == 60
    assert page["effective_days"] == 30
    assert [item["title"] for item in page["items"]] == ["Within limit"]
    assert page["total_count"] == 1
    assert page["total_pages"] == 1

    legacy = client.get("/api/v1/notifications", headers=auth(token))
    assert [item["title"] for item in legacy.json()] == ["Within limit"]


def test_recent_notifications_validate_cursor_limit_and_status(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)
    created = client.post(
        "/api/v1/notifications",
        headers=auth(token),
        json={
            "source": "codex",
            "session_id": "history-status",
            "title": "Acknowledged history",
            "body": "Done",
        },
    ).json()
    client.post(
        f"/api/v1/notifications/{created['id']}/ack",
        headers=auth(token),
        json={"reason": "user_confirmed"},
    )

    filtered = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params=[("status", "acknowledged"), ("days", "7"), ("limit", "20")],
    )
    assert filtered.status_code == 200, filtered.text
    assert [item["id"] for item in filtered.json()["items"]] == [created["id"]]

    invalid_cursor = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"cursor": "not-a-valid-cursor"},
    )
    assert invalid_cursor.status_code == 400

    too_large = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"limit": 101},
    )
    assert too_large.status_code == 422


def test_recent_notifications_filter_client_hidden_events_before_counting(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    notifications = [
        {
            "title": "Visible failure",
            "body": "Command failed",
            "metadata": {
                "hook_event_name": "StopFailure",
                "hook_status": "failed",
            },
        },
        {
            "title": "Codex idle",
            "body": "Session event received.",
            "metadata": {
                "hook_event_name": "Notification",
                "hook_status": "idle",
            },
        },
        {
            "title": "Codex needs confirmation",
            "body": "Run command?",
            "metadata": {
                "hook_event_name": "PermissionRequest",
                "notification_type": "approval_requested",
            },
        },
    ]
    for notification in notifications:
        response = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json={
                "source": "codex",
                "session_id": "history-visibility",
                **notification,
            },
        )
        assert response.status_code == 200, response.text

    normal = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"days": 1, "limit": 20},
    )
    assert normal.status_code == 200, normal.text
    assert [item["title"] for item in normal.json()["items"]] == [
        "Codex needs confirmation",
        "Visible failure",
    ]
    assert normal.json()["total_count"] == 2
    assert normal.json()["total_pages"] == 1

    auto_approval = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={
            "days": 1,
            "limit": 20,
            "suppress_codex_permission_requests": True,
        },
    )
    assert auto_approval.status_code == 200, auto_approval.text
    assert [item["title"] for item in auto_approval.json()["items"]] == ["Visible failure"]
    assert auto_approval.json()["total_count"] == 1
    assert auto_approval.json()["total_pages"] == 1

    unfiltered = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"days": 1, "limit": 2, "visible_only": False},
    )
    assert unfiltered.status_code == 200, unfiltered.text
    assert unfiltered.json()["total_count"] == 3
    assert unfiltered.json()["total_pages"] == 2


def test_recent_notifications_filter_by_machine_agent_tag_and_keyword(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    workstation = bind_tokens(client, name="WORKSTATION-01", platform="windows")
    laptop = bind_tokens(client, name="Build-Laptop", platform="windows")

    notifications = [
        (
            workstation["access_token"],
            {
                "source": "codex",
                "session_id": "nightly-build",
                "title": "Build completed",
                "body": "All verification jobs passed",
                "metadata": {"tag": "auto nightly"},
            },
        ),
        (
            laptop["access_token"],
            {
                "source": "claude",
                "session_id": "review-session",
                "title": "Review requested",
                "body": "Please inspect the patch",
                "metadata": {"tag": "manual_review"},
            },
        ),
        (
            workstation["access_token"],
            {
                "source": "codex",
                "session_id": "literal-tag",
                "title": "Coverage is complete",
                "body": "Reached the target",
                "metadata": {"tag": "100%"},
            },
        ),
    ]
    for token, payload in notifications:
        response = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json=payload,
        )
        assert response.status_code == 200, response.text

    options_response = client.get(
        "/api/v1/notifications/recent",
        headers=auth(workstation["access_token"]),
        params={"days": 1, "limit": 20},
    )
    assert options_response.status_code == 200, options_response.text
    filter_options = options_response.json()["filter_options"]
    assert [item["name"] for item in filter_options["machines"]] == [
        "Build-Laptop",
        "WORKSTATION-01",
    ]
    assert filter_options["agents"] == ["claude", "codex"]
    assert filter_options["tags"] == ["100%", "auto nightly", "manual_review"]
    assert filter_options["truncated"] is False

    renamed = client.patch(
        f"/api/v1/devices/{workstation['device']['id']}",
        headers=auth(workstation["access_token"]),
        json={"name": "Renamed-Workstation"},
    )
    assert renamed.status_code == 200, renamed.text

    def titles(**params):
        response = client.get(
            "/api/v1/notifications/recent",
            headers=auth(workstation["access_token"]),
            params={"days": 1, "limit": 20, **params},
        )
        assert response.status_code == 200, response.text
        page = response.json()
        assert page["total_count"] == len(page["items"])
        return [item["title"] for item in page["items"]]

    assert titles(machine="workstation") == ["Coverage is complete", "Build completed"]
    assert titles(machine="renamed-workstation") == ["Coverage is complete", "Build completed"]
    assert titles(agent="CLAUDE") == ["Review requested"]
    assert titles(tag="AUTO") == ["Build completed"]
    assert titles(q="verification jobs") == ["Build completed"]
    assert titles(machine="build-lap", agent="claude", tag="review") == ["Review requested"]
    assert titles(tag="%") == ["Coverage is complete"]

    filtered_options = client.get(
        "/api/v1/notifications/recent",
        headers=auth(workstation["access_token"]),
        params={"days": 1, "limit": 20, "agent": "claude", "tag": "review"},
    ).json()["filter_options"]
    assert [item["name"] for item in filtered_options["machines"]] == [
        "Build-Laptop",
        "Renamed-Workstation",
    ]
    assert filtered_options["agents"] == ["claude", "codex"]
    assert filtered_options["tags"] == ["100%", "auto nightly", "manual_review"]


def test_recent_notification_filter_options_are_bounded_and_safe(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    for index in range(101):
        tag = f"tag-{index:03d}"
        if index == 0:
            tag = f"\u202e{tag}"
        if index == 1:
            tag = f"{tag}-{'x' * 200}"
        if index == 2:
            tag = 0
        response = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json={
                "source": "codex",
                "session_id": f"options-{index}",
                "title": f"Option {index}",
                "body": "Option list bound test",
                "metadata": {"tag": tag},
            },
        )
        assert response.status_code == 200, response.text

    response = client.get(
        "/api/v1/notifications/recent",
        headers=auth(token),
        params={"days": 1, "limit": 1},
    )
    assert response.status_code == 200, response.text
    options = response.json()["filter_options"]
    assert len(options["tags"]) == 100
    assert options["truncated"] is True
    assert "tag-000" in options["tags"]
    assert "0" in options["tags"]
    assert all("\u202e" not in tag and len(tag) <= 120 for tag in options["tags"])


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


def test_windows_presence_summary_and_android_realtime_invalidation(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    desktop = bind_tokens(client, name="Desktop", platform="windows")
    phone = bind_tokens(client, name="Pixel", platform="android")

    initial = client.get(
        "/api/v1/devices/presence",
        headers=auth(phone["access_token"]),
    )
    assert initial.status_code == 200, initial.text
    assert initial.json()["any_unlocked_windows"] is False
    assert initial.json()["any_unlocked_unpaused_windows"] is False
    assert initial.json()["registered_windows"] == 1
    assert initial.json()["fresh_windows"] == 0
    assert initial.json()["windows_devices"][0]["effective_session_state"] == "unknown"

    pause_until = utc_now() + timedelta(hours=1)
    with client.websocket_connect(f"/api/v1/ws?token={phone['access_token']}") as websocket:
        unlocked = client.post(
            "/api/v1/devices/me/presence",
            headers=auth(desktop["access_token"]),
            json={
                "session_state": "unlocked",
                "notification_pause_until": pause_until.isoformat(),
                "suppress_codex_permission_requests": True,
            },
        )
        assert unlocked.status_code == 200, unlocked.text
        assert unlocked.json()["any_unlocked_windows"] is True
        assert unlocked.json()["any_unlocked_unpaused_windows"] is False
        assert unlocked.json()["fresh_windows"] == 1
        assert unlocked.json()["windows_devices"][0][
            "suppress_codex_permission_requests"
        ] is True
        event = websocket.receive_json()
        assert event["event_type"] == "device.presence_changed"
        assert event["device_id"] == desktop["device"]["id"]
        assert event["device_session_state"] == "unlocked"
        assert event["any_unlocked_windows"] is True
        assert event["any_unlocked_unpaused_windows"] is False

        devices = client.get(
            "/api/v1/devices",
            headers=auth(phone["access_token"]),
        )
        desktop_state = next(
            item for item in devices.json() if item["id"] == desktop["device"]["id"]
        )
        assert datetime.fromisoformat(desktop_state["notification_pause_until"]) == pause_until

        resumed = client.post(
            "/api/v1/devices/me/presence",
            headers=auth(desktop["access_token"]),
            json={"session_state": "unlocked", "notification_pause_until": None},
        )
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()["any_unlocked_windows"] is True
        assert resumed.json()["any_unlocked_unpaused_windows"] is True
        event = websocket.receive_json()
        assert event["device_session_state"] == "unlocked"
        assert event["any_unlocked_unpaused_windows"] is True

        paused_again = client.post(
            "/api/v1/devices/me/presence",
            headers=auth(desktop["access_token"]),
            json={
                "session_state": "unlocked",
                "notification_pause_until": pause_until.isoformat(),
            },
        )
        assert paused_again.status_code == 200, paused_again.text
        assert paused_again.json()["any_unlocked_windows"] is True
        assert paused_again.json()["any_unlocked_unpaused_windows"] is False
        event = websocket.receive_json()
        assert event["device_session_state"] == "unlocked"
        assert event["any_unlocked_unpaused_windows"] is False

        locked = client.post(
            "/api/v1/devices/me/presence",
            headers=auth(desktop["access_token"]),
            json={"session_state": "locked", "notification_pause_until": None},
        )
        assert locked.status_code == 200, locked.text
        assert locked.json()["any_unlocked_windows"] is False
        assert locked.json()["any_unlocked_unpaused_windows"] is False
        event = websocket.receive_json()
        assert event["event_type"] == "device.presence_changed"
        assert event["device_session_state"] == "locked"

        policy_changed = client.post(
            "/api/v1/devices/me/presence",
            headers=auth(desktop["access_token"]),
            json={
                "session_state": "locked",
                "notification_pause_until": None,
                "suppress_codex_permission_requests": True,
            },
        )
        assert policy_changed.status_code == 200, policy_changed.text
        assert policy_changed.json()["windows_devices"][0][
            "suppress_codex_permission_requests"
        ] is True
        event = websocket.receive_json()
        assert event["event_type"] == "device.presence_changed"
        assert event["device_session_state"] == "locked"

        devices = client.get(
            "/api/v1/devices",
            headers=auth(phone["access_token"]),
        )
        desktop_state = next(
            item for item in devices.json() if item["id"] == desktop["device"]["id"]
        )
        assert desktop_state["notification_pause_until"] is None


def test_presence_expires_and_android_cannot_report_windows_state(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    desktop = bind_tokens(client, name="Desktop", platform="windows")
    phone = bind_tokens(client, name="Pixel", platform="android")

    reported = client.post(
        "/api/v1/devices/me/presence",
        headers=auth(desktop["access_token"]),
        json={
            "session_state": "unlocked",
            "suppress_codex_permission_requests": True,
        },
    )
    assert reported.status_code == 200, reported.text

    stale_at = (utc_now() - timedelta(minutes=5)).isoformat()
    storage = app.state.storage
    with storage._lock, storage._conn:
        storage._conn.execute(
            "UPDATE devices SET session_state_updated_at = ? WHERE id = ?",
            (stale_at, desktop["device"]["id"]),
        )

    summary = client.get(
        "/api/v1/devices/presence",
        headers=auth(phone["access_token"]),
    )
    assert summary.status_code == 200, summary.text
    assert summary.json()["any_unlocked_windows"] is False
    assert summary.json()["fresh_windows"] == 0
    assert summary.json()["windows_devices"][0]["reported_session_state"] == "unlocked"
    assert summary.json()["windows_devices"][0]["effective_session_state"] == "unknown"
    assert summary.json()["windows_devices"][0][
        "suppress_codex_permission_requests"
    ] is True

    rejected = client.post(
        "/api/v1/devices/me/presence",
        headers=auth(phone["access_token"]),
        json={"session_state": "unlocked"},
    )
    assert rejected.status_code == 422


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


def test_bounded_event_window_initializes_and_recovers_without_full_history(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    for index in range(3):
        created = client.post(
            "/api/v1/notifications",
            headers=auth(token),
            json={
                "source": "codex",
                "session_id": f"bounded-{index}",
                "title": f"Completion {index}",
                "body": "Ready for review",
                "level": "success",
            },
        )
        assert created.status_code == 200, created.text

    legacy_events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    assert len(legacy_events) == 3

    initialized = client.get(
        "/api/v1/events",
        headers=auth(token),
        params={"limit": 2},
    )
    assert initialized.status_code == 200, initialized.text
    assert initialized.json() == {
        "events": [],
        "latest_event_id": legacy_events[-1]["event_id"],
        "cursor_found": None,
        "has_more": False,
    }

    bounded = client.get(
        "/api/v1/events",
        headers=auth(token),
        params={"since_event_id": legacy_events[0]["event_id"], "limit": 1},
    )
    assert bounded.status_code == 200, bounded.text
    assert [event["event_id"] for event in bounded.json()["events"]] == [
        legacy_events[1]["event_id"]
    ]
    assert bounded.json()["latest_event_id"] == legacy_events[-1]["event_id"]
    assert bounded.json()["cursor_found"] is True
    assert bounded.json()["has_more"] is True

    missing = client.get(
        "/api/v1/events",
        headers=auth(token),
        params={"since_event_id": "pruned-event", "limit": 2},
    )
    assert missing.status_code == 200, missing.text
    assert missing.json() == {
        "events": [],
        "latest_event_id": legacy_events[-1]["event_id"],
        "cursor_found": False,
        "has_more": False,
    }

    assert client.get(
        "/api/v1/events",
        headers=auth(token),
        params={"limit": 501},
    ).status_code == 422


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
    assert hook.json()["level"] == "important"
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


def test_hook_allows_explicit_external_title_and_level_overrides(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    overridden = client.post(
        "/api/v1/hooks/backup-cli",
        headers=auth(token),
        json={
            "event_type": "completed",
            "session_id": "nightly-backup",
            "message": "Database and attachments were backed up.",
            "notification_title": "Nightly backup is ready",
            "notification_level": "important",
            "metadata": {"ingest_source": "hook_bridge"},
        },
    )

    assert overridden.status_code == 200, overridden.text
    assert overridden.json()["source"] == "backup-cli"
    assert overridden.json()["title"] == "Nightly backup is ready"
    assert overridden.json()["level"] == "important"
    assert overridden.json()["body"] == "Database and attachments were backed up."

    normal_hook = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json={
            "hook_event_name": "Stop",
            "session_id": "normal-claude-hook",
            "title": "This remains the hook body",
        },
    )
    assert normal_hook.status_code == 200, normal_hook.text
    assert normal_hook.json()["title"] == "claude completed"
    assert normal_hook.json()["level"] == "success"
    assert normal_hook.json()["body"] == "This remains the hook body"


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
            "metadata": {"tag": "auto"},
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["level"] == "success"
    assert completed.json()["title"] == "claude completed"
    assert completed.json()["body"] == "Refactor finished."
    assert completed.json()["metadata"]["hook_event_name"] == "Stop"
    assert completed.json()["metadata"]["cwd"] == "I:/Projects/session_notify"
    assert completed.json()["metadata"]["tag"] == "auto"
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
    # 无内容 TaskCompleted(body_generated、无真实正文)是噪声,服务端创建层 suppress 不创建通知
    assert generic_completed.json() is None

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
    assert permission.json()["level"] == "important"
    assert permission.json()["title"] == "claude needs confirmation"


def test_cursor_hook_event_mapping(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    completed = client.post(
        "/api/v1/hooks/cursor",
        headers=auth(token),
        json={
            "event_type": "completed",
            "hook_event_name": "stop",
            "hook_status": "completed",
            "session_id": "cursor-conversation",
            "message": "Refactor finished.",
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["level"] == "success"
    assert completed.json()["title"] == "cursor completed"
    assert completed.json()["body"] == "Refactor finished."
    assert completed.json()["source"] == "cursor"

    question = client.post(
        "/api/v1/hooks/cursor",
        headers=auth(token),
        json={
            "event_type": "approval_requested",
            "hook_event_name": "preToolUse",
            "hook_status": "approval_requested",
            "tool_name": "AskQuestion",
            "prompt": "Which environment?",
            "session_id": "cursor-question",
        },
    )
    assert question.status_code == 200, question.text
    assert question.json()["level"] == "important"
    assert question.json()["title"] == "cursor needs confirmation"
    assert question.json()["body"] == "Which environment?"

    failed = client.post(
        "/api/v1/hooks/cursor",
        headers=auth(token),
        json={
            "event_type": "failed",
            "hook_event_name": "stop",
            "hook_status": "failed",
            "session_id": "cursor-error",
        },
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["level"] == "critical"
    assert failed.json()["title"] == "cursor needs attention"

    resolve = client.post(
        "/api/v1/hooks/cursor",
        headers=auth(token),
        json={
            "event_type": "postToolUse",
            "hook_event_name": "postToolUse",
            "hook_status": "postToolUse",
            "tool_name": "AskQuestion",
            "session_id": "cursor-question",
        },
    )
    assert resolve.status_code == 200, resolve.text
    assert resolve.json() is None

    aborted = client.post(
        "/api/v1/hooks/cursor",
        headers=auth(token),
        json={
            "event_type": "paused",
            "hook_event_name": "stop",
            "hook_status": "paused",
            "session_id": "cursor-aborted",
        },
    )
    assert aborted.status_code == 200, aborted.text
    assert aborted.json() is None


def test_cursor_generation_id_promoted_to_turn_id(tmp_path):
    app = create_app(tmp_path / "server.db")
    client = TestClient(app)
    token = bind(client)

    question = client.post(
        "/api/v1/hooks/cursor",
        headers=auth(token),
        json={
            "event_type": "approval_requested",
            "hook_event_name": "preToolUse",
            "hook_status": "approval_requested",
            "tool_name": "AskQuestion",
            "prompt": "Which environment?",
            "session_id": "cursor-generation",
            "metadata": {"raw": {"generation_id": "cursor-gen-99"}},
        },
    )
    assert question.status_code == 200, question.text
    assert question.json()["metadata"]["turn_id"] == "cursor-gen-99"


def test_requires_authorization(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    response = client.get("/api/v1/notifications")
    assert response.status_code == 401


def _hook_payload(
    event_name,
    session_id,
    command,
    *,
    event_type=None,
    cwd="I:/Projects/x",
    tool_name="Bash",
    turn_id=None,
):
    if event_name == "PermissionRequest":
        event_type = event_type or "approval_requested"
    else:
        event_type = event_type or "completed"
    raw = {"command": command, "cwd": cwd, "tool_name": tool_name}
    payload = {
        "hook_event_name": event_name,
        "event_type": event_type,
        "hook_status": event_type,
        "session_id": session_id,
        "cwd": cwd,
        "tool_name": tool_name,
        "metadata": {"raw": raw},
    }
    if turn_id is not None:
        payload["turn_id"] = turn_id
        raw["turn_id"] = turn_id
    return payload


def _claude_interactive_payload(
    event_name: str,
    session_id: str,
    *,
    transcript_path: str,
) -> dict:
    base = {
        "hook_event_name": event_name,
        "event_type": "approval_requested",
        "hook_status": "approval_requested",
        "session_id": session_id,
        "cwd": "R:\\",
        "transcript_path": transcript_path,
    }
    if event_name == "PermissionRequest":
        base.update({
            "prompt": "在 JavaScript 中，`typeof null` 的返回结果是什么？",
            "tool_name": "AskUserQuestion",
            "tool_input": {
                "questions": [{
                    "question": "在 JavaScript 中，`typeof null` 的返回结果是什么？",
                }],
            },
        })
    else:
        base.update({
            "notification_type": "permission_prompt",
            "message": "Claude needs your permission",
        })
    return base


def _claude_plan_payload(
    event_name: str,
    session_id: str,
    *,
    transcript_path: str,
) -> dict:
    base = {
        "hook_event_name": event_name,
        "event_type": "approval_requested",
        "hook_status": "approval_requested",
        "session_id": session_id,
        "cwd": "R:\\",
        "transcript_path": transcript_path,
    }
    if event_name == "PermissionRequest":
        base.update({
            "permission_mode": "plan",
            "tool_name": "ExitPlanMode",
            "metadata": {
                "raw": {
                    "hook_event_name": "PermissionRequest",
                    "permission_mode": "plan",
                    "tool_name": "ExitPlanMode",
                    "tool_input": {"plan": "# Network test plan"},
                },
            },
        })
    else:
        base.update({
            "notification_type": "permission_prompt",
            "message": "Claude Code needs your approval for the plan",
            "metadata": {
                "raw": {
                    "hook_event_name": "Notification",
                    "notification_type": "permission_prompt",
                    "message": "Claude Code needs your approval for the plan",
                },
            },
        })
    return base


def test_claude_interactive_permission_transports_share_one_notification(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    session_id = "s-interactive"
    transcript = "C:/Users/tester/.claude/projects/R--/s-interactive.jsonl"

    detailed = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "PermissionRequest",
            session_id,
            transcript_path=transcript,
        ),
    )
    generic = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "Notification",
            session_id,
            transcript_path=transcript,
        ),
    )

    assert detailed.status_code == 200, detailed.text
    assert generic.status_code == 200, generic.text
    assert generic.json()["id"] == detailed.json()["id"]
    assert generic.json()["body"] == detailed.json()["body"]
    assert generic.json()["metadata"]["hook_event_name"] == "PermissionRequest"
    assert generic.json()["metadata"]["event_family"] == "claude_permission_prompt"
    assert generic.json()["metadata"]["correlated_hook_events"] == [
        "permission_prompt",
        "permission_request",
    ]

    active = client.get("/api/v1/notifications", headers=auth(token)).json()
    assert [item["id"] for item in active] == [detailed.json()["id"]]
    created_events = [
        event
        for event in client.get("/api/v1/events", headers=auth(token)).json()["events"]
        if event["event_type"] == "notification.created"
        and event["notification"]["session_id"] == session_id
    ]
    assert len(created_events) == 1


def test_claude_plan_permission_remains_the_canonical_transport(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    session_id = "s-plan-confirmation"
    transcript = "C:/Users/tester/.claude/projects/R--/s-plan-confirmation.jsonl"

    permission = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_plan_payload(
            "PermissionRequest",
            session_id,
            transcript_path=transcript,
        ),
    )
    generic = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_plan_payload(
            "Notification",
            session_id,
            transcript_path=transcript,
        ),
    )

    assert permission.status_code == 200, permission.text
    assert generic.status_code == 200, generic.text
    assert permission.json()["body"] == "Session event received."
    assert generic.json()["id"] == permission.json()["id"]
    assert generic.json()["body"] == permission.json()["body"]
    assert generic.json()["metadata"]["hook_event_name"] == "PermissionRequest"
    assert generic.json()["metadata"]["tool_name"] == "ExitPlanMode"
    assert generic.json()["metadata"]["raw"]["tool_input"]["plan"] == "# Network test plan"

    created_events = [
        event
        for event in client.get("/api/v1/events", headers=auth(token)).json()["events"]
        if event["event_type"] == "notification.created"
        and event["notification"]["session_id"] == session_id
    ]
    assert len(created_events) == 1


def test_claude_interactive_detail_upserts_an_earlier_generic_prompt(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    session_id = "s-interactive-reverse"
    transcript = "C:/Users/tester/.claude/projects/R--/s-interactive-reverse.jsonl"

    generic = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "Notification",
            session_id,
            transcript_path=transcript,
        ),
    )
    detailed = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "PermissionRequest",
            session_id,
            transcript_path=transcript,
        ),
    )

    assert detailed.json()["id"] == generic.json()["id"]
    assert detailed.json()["body"] == "在 JavaScript 中，`typeof null` 的返回结果是什么？"
    created_events = [
        event
        for event in client.get("/api/v1/events", headers=auth(token)).json()["events"]
        if event["event_type"] == "notification.created"
        and event["notification"]["session_id"] == session_id
    ]
    assert len(created_events) == 2
    assert created_events[-1]["notification"]["id"] == generic.json()["id"]
    assert created_events[-1]["notification"]["body"] == detailed.json()["body"]


def test_acknowledged_claude_prompt_is_not_reopened_by_later_transport(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    session_id = "s-interactive-ack-race"
    transcript = "C:/Users/tester/.claude/projects/R--/s-interactive-ack-race.jsonl"

    detailed = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "PermissionRequest",
            session_id,
            transcript_path=transcript,
        ),
    ).json()
    acknowledged = client.post(
        f"/api/v1/notifications/{detailed['id']}/ack",
        headers=auth(token),
        json={"reason": "user_confirmed"},
    )
    assert acknowledged.status_code == 200, acknowledged.text

    late_generic = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "Notification",
            session_id,
            transcript_path=transcript,
        ),
    )
    assert late_generic.status_code == 200, late_generic.text
    assert late_generic.json()["id"] == detailed["id"]
    assert late_generic.json()["status"] == "acknowledged"
    assert late_generic.json()["updated_at"] == acknowledged.json()["notification"]["updated_at"]
    assert client.get("/api/v1/notifications", headers=auth(token)).json() == []


def test_claude_generic_prompt_correlates_to_the_nearest_question(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    session_id = "s-sequential-questions"
    transcript = "C:/Users/tester/.claude/projects/R--/s-sequential-questions.jsonl"

    first = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "PermissionRequest",
            session_id,
            transcript_path=transcript,
        ),
    ).json()
    client.post(
        f"/api/v1/notifications/{first['id']}/ack",
        headers=auth(token),
        json={"reason": "user_confirmed"},
    )
    second = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "PermissionRequest",
            session_id,
            transcript_path=transcript,
        ),
    ).json()
    generic = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_claude_interactive_payload(
            "Notification",
            session_id,
            transcript_path=transcript,
        ),
    ).json()

    assert first["id"] != second["id"]
    assert generic["id"] == second["id"]
    assert generic["id"] != first["id"]
    active_ids = {
        item["id"]
        for item in client.get("/api/v1/notifications", headers=auth(token)).json()
    }
    assert active_ids == {second["id"]}


def test_acknowledging_one_legacy_claude_transport_acknowledges_its_sibling(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    common = {
        "source": "claude",
        "session_id": "s-legacy-double",
        "title": "claude needs confirmation",
        "level": "critical",
        "metadata": {
            "cwd": "R:\\",
            "transcript_path": "C:/Users/tester/.claude/projects/R--/s-legacy-double.jsonl",
        },
    }
    detailed_payload = {
        **common,
        "body": "Choose a JavaScript answer",
        "metadata": {
            **common["metadata"],
            "hook_event_name": "PermissionRequest",
            "tool_name": "AskUserQuestion",
        },
    }
    generic_payload = {
        **common,
        "body": "Claude needs your permission",
        "metadata": {
            **common["metadata"],
            "hook_event_name": "Notification",
            "notification_type": "permission_prompt",
        },
    }
    detailed = client.post(
        "/api/v1/notifications",
        headers=auth(token),
        json=detailed_payload,
    ).json()
    generic = client.post(
        "/api/v1/notifications",
        headers=auth(token),
        json=generic_payload,
    ).json()
    assert detailed["id"] != generic["id"]

    response = client.post(
        f"/api/v1/notifications/{generic['id']}/ack",
        headers=auth(token),
        json={"reason": "user_confirmed"},
    )
    assert response.status_code == 200, response.text
    assert client.get("/api/v1/notifications", headers=auth(token)).json() == []
    acknowledged_ids = {
        event["notification_id"]
        for event in client.get("/api/v1/events", headers=auth(token)).json()["events"]
        if event["event_type"] == "notification.acknowledged"
    }
    assert {detailed["id"], generic["id"]} <= acknowledged_ids


def _codex_terminal_failure_payload(
    *,
    session_id: str,
    turn_id: str,
    ingest_source: str,
):
    is_app_server = ingest_source == "app_server"
    return {
        "event_type": "terminal_failure" if is_app_server else "failed",
        "hook_event_name": "turn/completed" if is_app_server else "Stop",
        "hook_status": "failed",
        "session_id": session_id,
        "turn_id": turn_id,
        "message": "stream disconnected before completion",
        "metadata": {
            "ingest_source": ingest_source,
            "event_correlation": "remote_correlated" if is_app_server else "hook_only",
            "app_server_port": 4500 if is_app_server else None,
        },
    }


def test_codex_terminal_failure_is_deduplicated_across_app_server_and_hook(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    app_server = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_codex_terminal_failure_payload(
            session_id="thread-dedupe",
            turn_id="turn-dedupe",
            ingest_source="app_server",
        ),
    )
    hook = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_codex_terminal_failure_payload(
            session_id="thread-dedupe",
            turn_id="turn-dedupe",
            ingest_source="hook_bridge",
        ),
    )

    assert app_server.status_code == 200, app_server.text
    assert hook.status_code == 200, hook.text
    assert app_server.json()["level"] == "critical"
    assert hook.json()["level"] == "critical"
    assert hook.json()["id"] == app_server.json()["id"]
    assert hook.json()["metadata"]["ingest_sources"] == ["app_server", "hook_bridge"]
    assert hook.json()["metadata"]["event_correlation"] == "remote_correlated"

    created = [
        event
        for event in client.get("/api/v1/events", headers=auth(token)).json()["events"]
        if event["event_type"] == "notification.created"
    ]
    assert len(created) == 1


def test_codex_terminal_failure_dedupe_survives_server_restart(tmp_path):
    db_path = tmp_path / "server.db"
    first_client = TestClient(create_app(db_path))
    token = bind(first_client)
    first = first_client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_codex_terminal_failure_payload(
            session_id="thread-restart",
            turn_id="turn-restart",
            ingest_source="hook_bridge",
        ),
    )
    assert first.status_code == 200, first.text

    second_client = TestClient(create_app(db_path))
    duplicate = second_client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_codex_terminal_failure_payload(
            session_id="thread-restart",
            turn_id="turn-restart",
            ingest_source="app_server",
        ),
    )
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["id"] == first.json()["id"]
    assert duplicate.json()["metadata"]["ingest_sources"] == ["app_server", "hook_bridge"]


def test_hook_delivery_id_makes_replayed_claude_failure_idempotent(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    payload = {
        "hook_event_name": "StopFailure",
        "event_type": "failed",
        "hook_status": "failed",
        "session_id": "claude-offline",
        "message": "API Error: connection failed",
        "metadata": {
            "ingest_source": "hook_bridge",
            "delivery_id": "offline-delivery-1",
            "delivery_guarantee": "durable_outbox",
        },
    }

    first = client.post("/api/v1/hooks/claude", headers=auth(token), json=payload)
    replay = client.post("/api/v1/hooks/claude", headers=auth(token), json=payload)

    assert first.status_code == 200, first.text
    assert replay.status_code == 200, replay.text
    assert first.json()["level"] == "critical"
    assert replay.json()["id"] == first.json()["id"]
    created = [
        event
        for event in client.get("/api/v1/events", headers=auth(token)).json()["events"]
        if event["event_type"] == "notification.created"
    ]
    assert len(created) == 1


def test_hook_delivery_id_makes_replayed_normal_update_idempotent(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    payload = {
        "event_type": "completed",
        "session_id": "external-offline",
        "message": "Backup completed",
        "notification_title": "Backup is ready",
        "notification_level": "success",
        "metadata": {
            "ingest_source": "hook_bridge",
            "delivery_id": "offline-normal-delivery-1",
            "delivery_guarantee": "retry_on_failure_outbox",
        },
    }

    first = client.post("/api/v1/hooks/backup-cli", headers=auth(token), json=payload)
    replay = client.post("/api/v1/hooks/backup-cli", headers=auth(token), json=payload)

    assert first.status_code == 200, first.text
    assert replay.status_code == 200, replay.text
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["title"] == "Backup is ready"
    created = [
        event
        for event in client.get("/api/v1/events", headers=auth(token)).json()["events"]
        if event["event_type"] == "notification.created"
    ]
    assert len(created) == 1


def test_posttooluse_resolves_matching_permission_request(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    permission_payload = _hook_payload(
        "PermissionRequest", "s-perm", "npm test", turn_id="turn-perm"
    )
    # 旧 Bridge 只在 metadata.raw 中保留 turn_id；服务端仍应提升并参与匹配。
    permission_payload.pop("turn_id")
    perm = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=permission_payload)
    assert perm.status_code == 200, perm.text
    assert perm.json()["title"] == "claude needs confirmation"
    assert perm.json()["metadata"]["turn_id"] == "turn-perm"
    perm_id = perm.json()["id"]

    post_payload = _hook_payload(
        "PostToolUse", "s-perm", "npm test", turn_id="turn-perm"
    )
    post_payload.pop("turn_id")
    post = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=post_payload)
    assert post.status_code == 200, post.text

    active = client.get("/api/v1/notifications", headers=auth(token)).json()
    assert perm_id not in [item["id"] for item in active]
    assert "claude needs confirmation" not in [item["title"] for item in active]
    # PostToolUse 是传输信号(用于 resolve 权限),服务端创建层 suppress:自身不创建通知,
    # 故 active 为空(perm 已被 resolve,PostToolUse 未创建)。
    assert active == []
    assert post.json() is None

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    ack_events = [e for e in events if e["event_type"] == "notification.acknowledged"]
    assert len(ack_events) == 1
    assert ack_events[0]["notification_id"] == perm_id
    assert ack_events[0]["reason"] == "auto_resolved"


def test_posttooluse_does_not_resolve_same_command_from_another_turn(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    earlier = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-turns", "npm test", turn_id="turn-a"),
    )
    later = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-turns", "npm test", turn_id="turn-b"),
    )
    assert earlier.status_code == 200 and later.status_code == 200

    post = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PostToolUse", "s-turns", "npm test", turn_id="turn-a"),
    )
    assert post.status_code == 200, post.text

    active_ids = {
        item["id"]
        for item in client.get("/api/v1/notifications", headers=auth(token)).json()
    }
    assert earlier.json()["id"] not in active_ids
    assert later.json()["id"] in active_ids


def test_posttooluse_with_different_turn_is_noop(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    permission = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-turn-mismatch", "npm test",
                           turn_id="turn-a"),
    )
    post = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PostToolUse", "s-turn-mismatch", "npm test",
                           turn_id="turn-b"),
    )
    assert permission.status_code == 200 and post.status_code == 200

    active_ids = {
        item["id"]
        for item in client.get("/api/v1/notifications", headers=auth(token)).json()
    }
    assert permission.json()["id"] in active_ids


def test_posttooluse_turn_id_falls_back_to_one_legacy_permission(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    permission = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-legacy-turn", "npm test"),
    )
    post = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_hook_payload("PostToolUse", "s-legacy-turn", "npm test",
                           turn_id="turn-new"),
    )
    assert permission.status_code == 200 and post.status_code == 200

    active_ids = {
        item["id"]
        for item in client.get("/api/v1/notifications", headers=auth(token)).json()
    }
    assert permission.json()["id"] not in active_ids


def test_posttooluse_does_not_guess_between_ambiguous_permissions(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    legacy_a = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-ambiguous", "npm test"),
    )
    legacy_b = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-ambiguous", "npm test"),
    )
    post = client.post(
        "/api/v1/hooks/claude",
        headers=auth(token),
        json=_hook_payload("PostToolUse", "s-ambiguous", "npm test",
                           turn_id="turn-new"),
    )
    assert legacy_a.status_code == 200 and legacy_b.status_code == 200
    assert post.status_code == 200

    active_ids = {
        item["id"]
        for item in client.get("/api/v1/notifications", headers=auth(token)).json()
    }
    assert {legacy_a.json()["id"], legacy_b.json()["id"]} <= active_ids

    same_turn_a = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-same-turn", "npm test",
                           turn_id="turn-shared"),
    )
    same_turn_b = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", "s-same-turn", "npm test",
                           turn_id="turn-shared"),
    )
    same_turn_post = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PostToolUse", "s-same-turn", "npm test",
                           turn_id="turn-shared"),
    )
    assert same_turn_a.status_code == 200 and same_turn_b.status_code == 200
    assert same_turn_post.status_code == 200

    active_ids = {
        item["id"]
        for item in client.get("/api/v1/notifications", headers=auth(token)).json()
    }
    assert {same_turn_a.json()["id"], same_turn_b.json()["id"]} <= active_ids


def test_posttooluse_without_match_is_noop(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    post = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PostToolUse", "s-alone", "npm test"))
    assert post.status_code == 200, post.text
    assert post.json() is None  # PostToolUse 被 suppress,不创建通知

    events = client.get("/api/v1/events", headers=auth(token)).json()["events"]
    assert all(e["event_type"] != "notification.acknowledged" for e in events)
    # PostToolUse 不创建通知 → active 为空(无匹配 permission 也无事可 resolve)
    assert client.get("/api/v1/notifications", headers=auth(token)).json() == []


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


def test_plan_mode_stop_keeps_implementation_confirmation(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    session_id = "s-plan-ready"

    old_permission = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json=_hook_payload("PermissionRequest", session_id, "read plan inputs"),
    )
    assert old_permission.status_code == 200, old_permission.text
    old_permission_id = old_permission.json()["id"]

    plan_ready = client.post(
        "/api/v1/hooks/codex",
        headers=auth(token),
        json={
            "hook_event_name": "Stop",
            "event_type": "approval_requested",
            "hook_status": "approval_requested",
            "permission_mode": "plan",
            "session_id": session_id,
            "metadata": {"raw": {"permission_mode": "plan"}},
        },
    )
    assert plan_ready.status_code == 200, plan_ready.text
    assert plan_ready.json()["title"] == "codex needs confirmation"
    assert plan_ready.json()["level"] == "important"
    assert plan_ready.json()["body"] == "Plan is ready. Choose whether to implement it."
    assert plan_ready.json()["metadata"]["permission_mode"] == "plan"
    assert plan_ready.json()["metadata"]["body_generated"] is False

    active_ids = {
        item["id"]
        for item in client.get("/api/v1/notifications", headers=auth(token)).json()
    }
    assert old_permission_id not in active_ids
    assert plan_ready.json()["id"] in active_ids


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


def test_receive_hook_suppresses_noise_but_keeps_value(tmp_path):
    # PostToolUse/idle/无内容 completed 是噪声,服务端创建层不创建通知(返回 null);
    # needs-confirmation/failure/有内容的通知正常创建。
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    # PostToolUse:被 suppress(传输信号,用于 resolve 权限)
    post = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PostToolUse", "s-ptu", "npm test"))
    assert post.status_code == 200
    assert post.json() is None

    # 无内容 Stop(contentless completed):被 suppress
    stop = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("Stop", "s-stop", ""))
    assert stop.status_code == 200
    assert stop.json() is None

    # idle:被 suppress
    idle = client.post("/api/v1/hooks/claude", headers=auth(token), json={
        "hook_event_name": "Notification",
        "notification_type": "idle_prompt",
        "session_id": "s-idle",
    })
    assert idle.status_code == 200
    assert idle.json() is None

    # needs-confirmation:保留(important)
    perm = client.post("/api/v1/hooks/claude", headers=auth(token),
                       json=_hook_payload("PermissionRequest", "s-perm", "npm test"))
    assert perm.status_code == 200
    assert perm.json()["title"] == "claude needs confirmation"
    assert perm.json()["level"] == "important"

    # failure:保留(critical)——非 contentless completed
    fail = client.post("/api/v1/hooks/claude", headers=auth(token), json={
        "hook_event_name": "StopFailure",
        "event_type": "failure",
        "hook_status": "failed",
        "message": "boom",
        "session_id": "s-fail",
    })
    assert fail.status_code == 200
    assert fail.json()["title"] == "claude needs attention"
    assert fail.json()["level"] == "critical"

    # 有内容 completed(带 last_assistant_message):保留(success)
    done = client.post("/api/v1/hooks/claude", headers=auth(token), json={
        "hook_event_name": "Stop",
        "last_assistant_message": "Refactor finished.",
        "session_id": "s-done",
    })
    assert done.status_code == 200
    assert done.json()["title"] == "claude completed"
    assert done.json()["body"] == "Refactor finished."

    # 只有 3 条有价值通知进入 active(perm/fail/done),噪声全部未创建
    titles = sorted(item["title"] for item in client.get("/api/v1/notifications", headers=auth(token)).json())
    assert titles == ["claude completed", "claude needs attention", "claude needs confirmation"]


def test_hook_failure_severity_wins_over_approval_keyword(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    response = client.post("/api/v1/hooks/claude", headers=auth(token), json={
        "hook_event_name": "PermissionError",
        "event_type": "permission_error",
        "hook_status": "failed",
        "message": "Permission request failed.",
        "session_id": "s-permission-error",
    })

    assert response.status_code == 200
    assert response.json()["title"] == "claude needs attention"
    assert response.json()["level"] == "critical"


def test_direct_non_hook_idle_notification_remains_visible(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)

    response = client.post("/api/v1/notifications", headers=auth(token), json={
        "source": "session",
        "session_id": "s-idle-reminder",
        "title": "Session idle reminder",
        "body": "No activity has been recorded recently.",
        "level": "info",
        "metadata": {},
    })

    assert response.status_code == 200
    active = client.get("/api/v1/notifications", headers=auth(token)).json()
    assert [item["id"] for item in active] == [response.json()["id"]]


def test_receive_hook_suppresses_internal_codex_memory_consolidation_only(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    token = bind(client)
    consolidation = {
        "hook_event_name": "Stop",
        "event_type": "completed",
        "hook_status": "completed",
        "message": "Consolidation complete.",
        "session_id": "s-memory-consolidation",
        "cwd": r"C:\Users\tester\.codex\memories",
        "permission_mode": "bypassPermissions",
        "metadata": {
            "raw": {
                "cwd": r"C:\Users\tester\.codex\memories",
                "permission_mode": "bypassPermissions",
                "transcript_path": None,
            }
        },
    }

    hidden = client.post("/api/v1/hooks/codex", headers=auth(token), json=consolidation)
    assert hidden.status_code == 200, hidden.text
    assert hidden.json() is None

    interactive = {
        **consolidation,
        "session_id": "s-interactive-memory-work",
        "transcript_path": r"C:\Users\tester\.codex\sessions\interactive.jsonl",
    }
    kept = client.post("/api/v1/hooks/codex", headers=auth(token), json=interactive)
    assert kept.status_code == 200, kept.text
    assert kept.json()["title"] == "codex completed"

    active = client.get("/api/v1/notifications", headers=auth(token)).json()
    assert [item["session_id"] for item in active] == ["s-interactive-memory-work"]


def test_lifespan_cleans_legacy_noise_notifications(tmp_path):
    from app.storage import Storage
    from app.schemas import EventType, NotificationCreate, NotificationLevel, NotificationStatus

    db_path = tmp_path / "s.db"
    storage = Storage(db_path)
    # 模拟"创建层类型过滤"上线前的历史堆积:active 的噪声类(PostToolUse/无内容 completed/idle)
    posttooluse, _ = storage.create_notification(NotificationCreate(
        source="claude", session_id="s-ptu", title="claude update",
        body="Session event received.", level=NotificationLevel.info,
        expires_at=utc_now() + timedelta(hours=24),
        metadata={"hook_event_name": "PostToolUse", "body_generated": True},
    ))
    completed, _ = storage.create_notification(NotificationCreate(
        source="claude", session_id="s-done", title="claude completed",
        body="Session event received.", level=NotificationLevel.success,
        expires_at=utc_now() + timedelta(hours=24),
        metadata={"hook_event_name": "TaskCompleted", "body_generated": True},
    ))
    idle, _ = storage.create_notification(NotificationCreate(
        source="claude", session_id="s-idle", title="claude idle",
        body="Session event received.", level=NotificationLevel.important,
        expires_at=utc_now() + timedelta(hours=24),
        metadata={"hook_event_name": "Notification", "notification_type": "idle_prompt", "body_generated": True},
    ))
    consolidation, _ = storage.create_notification(NotificationCreate(
        source="codex", session_id="s-memory-consolidation", title="codex completed",
        body="Consolidation complete.", level=NotificationLevel.success,
        expires_at=utc_now() + timedelta(hours=24),
        metadata={
            "hook_event_name": "Stop",
            "hook_status": "completed",
            "body_generated": False,
            "cwd": r"C:\Users\tester\.codex\memories",
            "permission_mode": "bypassPermissions",
        },
    ))
    # failure 类 hook 通知:有价值,两个迁移都不应动它
    fail, _ = storage.create_notification(NotificationCreate(
        source="claude", session_id="s-fail", title="claude needs attention",
        body="boom", level=NotificationLevel.important,
        expires_at=utc_now() + timedelta(hours=24),
        metadata={"hook_event_name": "StopFailure", "hook_status": "failed", "body_generated": False},
    ))
    # 非 hook 来源的用户通知:不受 hook 噪声迁移影响
    user_notif, _ = storage.create_notification(NotificationCreate(
        source="session", session_id="s-user", title="Standup",
        body="meeting", level=NotificationLevel.important,
        expires_at=utc_now() + timedelta(hours=24),
        metadata={},
    ))
    storage.close()

    client = TestClient(create_app(db_path))
    with client:
        token = bind(client)
        active_ids = {item["id"] for item in client.get("/api/v1/notifications", headers=auth(token)).json()}

    # 噪声类被清理;有价值通知(failure/用户通知)保留
    assert posttooluse.id not in active_ids
    assert completed.id not in active_ids
    assert idle.id not in active_ids
    assert consolidation.id not in active_ids
    assert fail.id in active_ids
    assert user_notif.id in active_ids

    storage = Storage(db_path)
    acked_ids = {n.id for n in storage.list_notifications([NotificationStatus.acknowledged])}
    assert {posttooluse.id, completed.id, idle.id, consolidation.id} <= acked_ids
    cleanup_events = [
        e for e in storage.events_after(None)
        if e.event_type == EventType.notification_acknowledged
        and e.notification_id in {posttooluse.id, completed.id, idle.id, consolidation.id}
        and e.reason == "migration_cleanup"
    ]
    assert len(cleanup_events) == 4
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
    candidates = issued.json()["candidate_base_urls"]
    assert isinstance(candidates, list)
    for url in candidates:  # 形如 https://192.168.1.20:8765
        assert url.startswith(("http://", "https://"))
        assert url.split("://", 1)[1].count(":") == 1
    fingerprint = issued.json()["server_fingerprint"]
    assert fingerprint is None or len(fingerprint) == 64  # 证书读不到时为 None

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


def test_pair_status_reports_consumed(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    host = bind_tokens(client, name="Host", platform="windows")
    code = client.post("/api/v1/devices/pair/issue", headers=auth(host["access_token"])).json()["code"]

    pending = client.post("/api/v1/devices/pair/status", headers=auth(host["access_token"]), json={"code": code})
    assert pending.status_code == 200, pending.text
    assert pending.json()["consumed"] is False
    assert pending.json()["expired"] is False

    client.post("/api/v1/devices/pair/consume", json={"code": code, "name": "Pixel", "platform": "android"})
    consumed = client.post("/api/v1/devices/pair/status", headers=auth(host["access_token"]), json={"code": code})
    assert consumed.json()["consumed"] is True
    assert consumed.json()["consumed_device_name"] == "Pixel"


def test_pair_status_requires_bearer(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    assert client.post("/api/v1/devices/pair/status", json={"code": "ABCD-EFGH"}).status_code == 401


def test_pair_status_unknown_code_404(tmp_path):
    client = TestClient(create_app(tmp_path / "server.db"))
    host = bind_tokens(client)
    resp = client.post("/api/v1/devices/pair/status", headers=auth(host["access_token"]), json={"code": "NOPE-NOPE"})
    assert resp.status_code == 404


def test_pair_status_expired_not_consumed(tmp_path):
    from app.storage import _dt

    client = TestClient(create_app(tmp_path / "server.db"))
    host = bind_tokens(client)
    code = client.post("/api/v1/devices/pair/issue", headers=auth(host["access_token"])).json()["code"]
    storage = client.app.state.storage
    with storage._lock, storage._conn:
        storage._conn.execute("UPDATE pair_codes SET expires_at = ?", (_dt(utc_now() - timedelta(seconds=1)),))
    resp = client.post("/api/v1/devices/pair/status", headers=auth(host["access_token"]), json={"code": code})
    assert resp.status_code == 200
    assert resp.json()["consumed"] is False
    assert resp.json()["expired"] is True


def test_pair_consume_broadcasts_to_issuer(tmp_path):
    import hashlib

    client = TestClient(create_app(tmp_path / "server.db"))
    host = bind_tokens(client, name="Host", platform="windows")
    with client.websocket_connect("/api/v1/ws?token=" + host["access_token"]) as ws:
        code = client.post("/api/v1/devices/pair/issue", headers=auth(host["access_token"])).json()["code"]
        consumed = client.post(
            "/api/v1/devices/pair/consume",
            json={"code": code, "name": "Pixel", "platform": "android"},
        )
        assert consumed.status_code == 200, consumed.text
        event = ws.receive_json()
        assert event["event_type"] == "pair.consumed"
        assert event["pair_code_hash"] == hashlib.sha256(code.encode("utf-8")).hexdigest()
        assert event["pair_consumed_device_name"] == "Pixel"
        assert event["notification"] is None


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
    presence = client.post(
        "/api/v1/devices/me/presence",
        headers=auth(first.json()["access_token"]),
        json={"session_state": "unlocked"},
    )
    assert presence.status_code == 200, presence.text

    # 裸 bind(无 refresh)被拒
    assert client.post("/api/v1/devices/bind", json={"name": "Sneak", "platform": "windows"}).status_code == 401

    # 带有效旧 refresh_token → 本机 rebind 放行:同一设备、换发新 token、轮换 refresh
    rebound = client.post("/api/v1/devices/bind", json={
        "name": "Host", "platform": "windows", "refresh_token": old_refresh
    })
    assert rebound.status_code == 200, rebound.text
    assert rebound.json()["device"]["id"] == device_id
    assert rebound.json()["device"]["session_state"] == "unknown"
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
