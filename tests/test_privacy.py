from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.privacy import (
    PRIVACY_HIDDEN_BODY,
    canonicalize_privacy_metadata,
    normalize_privacy_tag,
    redact_notification_for_device,
)
from app.schemas import NotificationLevel, NotificationPublic, NotificationStatus, utc_now


def test_normalize_privacy_tag_accepts_hide_and_local_only():
    assert normalize_privacy_tag(" HIDE ") == "hide"
    assert normalize_privacy_tag("Local") == "local"
    assert normalize_privacy_tag("hide\u202e") == "hide"
    assert normalize_privacy_tag("secret") is None
    assert normalize_privacy_tag("") is None
    assert normalize_privacy_tag(1) is None


def test_canonicalize_privacy_metadata_keeps_a_single_canonical_key():
    assert canonicalize_privacy_metadata({"privacyTag": "LOCAL", "cwd": "I:/proj"}) == {
        "cwd": "I:/proj",
        "privacy_tag": "local",
    }
    assert canonicalize_privacy_metadata({"privacy_tag": "nope", "tag": "auto"}) == {"tag": "auto"}


def _notification(body: str, *, origin: str | None, privacy: str | None) -> NotificationPublic:
    now = utc_now()
    metadata = {"privacy_tag": privacy} if privacy else {}
    return NotificationPublic(
        id="n1",
        source="codex",
        session_id="s1",
        origin_device_id=origin,
        title="Done",
        body=body,
        level=NotificationLevel.success,
        status=NotificationStatus.active,
        created_at=now,
        updated_at=now,
        requires_ack=True,
        metadata=metadata,
    )


def test_redact_notification_for_device_hides_or_keeps_local_body():
    secret = _notification("secret body", origin="pc-1", privacy="hide")
    assert redact_notification_for_device(secret, "pc-1").body == PRIVACY_HIDDEN_BODY
    assert redact_notification_for_device(secret, "phone").body == PRIVACY_HIDDEN_BODY

    local = _notification("secret body", origin="pc-1", privacy="local")
    assert redact_notification_for_device(local, "pc-1").body == "secret body"
    assert redact_notification_for_device(local, "phone").body == PRIVACY_HIDDEN_BODY
    assert redact_notification_for_device(local, None).body == PRIVACY_HIDDEN_BODY


@pytest.mark.parametrize("mode", ["hide", "local"])
@pytest.mark.parametrize("use_hook", [False, True])
def test_private_metadata_is_redacted_on_every_distribution_path(tmp_path, mode, use_hook):
    app = create_app(tmp_path / "privacy.db")
    secret = "PRIVATE_BODY_MUST_NOT_REACH_REMOTE_DEVICE"
    metadata = {
        "privacy_tag": mode, "tag": "nightly", "cwd": "I:/project", "body_generated": False,
        "hook_event_name": "PreToolUse", "tool_name": "functions.request_user_input_async",
        "turn_id": "turn-1", "raw": {"last_assistant_message": secret},
        "tool_input": {"questions": [{"title": secret}]}, "toolResponse": secret,
        "prompt": secret, "command": secret, "additional_details": secret,
        "diagnostics": {"unexpected_field": secret},
        "codex_async": {"kind": "asked", "call_id": "call-1", "unexpected_field": secret},
    }
    with TestClient(app) as client:
        def bind(name):
            result = client.post("/api/v1/devices/bind", json={"name": name, "platform": "windows"})
            assert result.status_code == 200
            return {"Authorization": "Bearer " + result.json()["access_token"]}

        origin, remote = bind("origin"), bind("remote")
        with client.websocket_connect("/api/v1/ws", headers=origin) as origin_ws:
            with client.websocket_connect("/api/v1/ws", headers=remote) as remote_ws:
                payload = {"session_id": "privacy", "metadata": metadata}
                if use_hook:
                    payload.update(hook_event_name="PreToolUse", event_type="approval_requested", prompt=secret)
                    url = "/api/v1/hooks/codex"
                else:
                    payload.update(source="codex", title="Private notification", body=secret, level="info")
                    url = "/api/v1/notifications"
                response = client.post(url, headers=origin, json=payload)
                assert response.status_code == 200, response.text
                created = response.json()
                local_event = origin_ws.receive_json()
                remote_event = remote_ws.receive_json()
                assert (secret in json.dumps(created)) == (mode == "local")
                assert (secret in json.dumps(local_event)) == (mode == "local")
                assert secret not in json.dumps(remote_event)
                public = remote_event["notification"]["metadata"]
                assert public["tag"] == "nightly" and public["cwd"] == "I:/project"
                assert public["tool_name"] == "functions.request_user_input_async"
                assert public["codex_async"] == {"kind": "asked", "call_id": "call-1"}

        for url in ("/api/v1/notifications", "/api/v1/notifications/recent", "/api/v1/events"):
            result = client.get(url, headers=remote)
            assert result.status_code == 200, result.text
            assert secret not in result.text
        ack = client.post(f"/api/v1/notifications/{created['id']}/ack", headers=remote, json={})
        assert ack.status_code == 200 and secret not in ack.text
        stored = app.state.storage.list_notifications([NotificationStatus.acknowledged])[0]
        assert stored.body == secret
        assert stored.metadata["raw"]["last_assistant_message"] == secret
        assert stored.metadata["diagnostics"]["unexpected_field"] == secret


def test_already_masked_body_does_not_bypass_metadata_redaction():
    notification = _notification("***", origin="pc", privacy="hide").model_copy(update={
        "metadata": {"privacy_tag": "hide", "raw": "private", "toolInput": {"text": "private"}},
    })
    redacted = redact_notification_for_device(notification, "pc")
    assert redacted.metadata == {"privacy_tag": "hide"}
    assert notification.metadata["raw"] == "private"
    assert redact_notification_for_device(redacted, "pc") is redacted
