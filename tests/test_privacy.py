from __future__ import annotations

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
