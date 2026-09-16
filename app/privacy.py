"""通知正文隐私：SESSION_NOTIFY_PRIVACY_TAG。

存储保持明文。REST / WebSocket 下发时，若查看设备不应看到正文，则替换为 `***`。
"""

from __future__ import annotations

import json
from typing import Any

from .schemas import NotificationPublic, SyncEvent

PRIVACY_HIDDEN_BODY = "***"
PRIVACY_HIDE = "hide"
PRIVACY_LOCAL = "local"
PRIVACY_MODES = frozenset({PRIVACY_HIDE, PRIVACY_LOCAL})
PRIVACY_METADATA_KEYS = (
    "privacy_tag",
    "session_notify_privacy_tag",
    "privacyTag",
    "sessionNotifyPrivacyTag",
)


def _is_unsafe_format_control(code_point: int) -> bool:
    return (
        code_point in {0x00AD, 0x061C, 0x180E, 0xFEFF}
        or 0x200B <= code_point <= 0x200F
        or 0x202A <= code_point <= 0x202E
        or 0x2060 <= code_point <= 0x206F
    )


def normalize_privacy_tag(value: object) -> str | None:
    """返回规范的 `hide` / `local`；未使用或无法识别时返回 None。"""
    if not isinstance(value, str):
        return None
    cleaned: list[str] = []
    pending_space = False
    for character in value[:4096]:
        code_point = ord(character)
        if _is_unsafe_format_control(code_point):
            continue
        if character.isspace() or code_point <= 0x1F or 0x7F <= code_point <= 0x9F:
            pending_space = bool(cleaned)
            continue
        if pending_space:
            cleaned.append(" ")
            pending_space = False
        cleaned.append(character)
    mode = "".join(cleaned).strip().lower()
    return mode if mode in PRIVACY_MODES else None


def privacy_mode_from_metadata(metadata: object) -> str | None:
    if not isinstance(metadata, dict):
        return None
    for key in PRIVACY_METADATA_KEYS:
        mode = normalize_privacy_tag(metadata.get(key))
        if mode:
            return mode
    return None


def canonicalize_privacy_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """存储的 metadata 最多保留一个规范的 `privacy_tag`。"""
    result = dict(metadata or {})
    mode = privacy_mode_from_metadata(result)
    for key in PRIVACY_METADATA_KEYS:
        result.pop(key, None)
    if mode:
        result["privacy_tag"] = mode
    return result


def body_visible_to_device(
    metadata: object,
    origin_device_id: str | None,
    viewer_device_id: str | None,
) -> bool:
    mode = privacy_mode_from_metadata(metadata)
    if mode == PRIVACY_HIDE:
        return False
    if mode == PRIVACY_LOCAL:
        origin = str(origin_device_id or "").strip()
        viewer = str(viewer_device_id or "").strip()
        return bool(origin) and origin == viewer
    return True


def sqlite_body_visible_to_device(
    metadata_json: object,
    origin_device_id: object,
    viewer_device_id: object,
) -> int:
    try:
        metadata = json.loads(str(metadata_json or "{}"))
        if not isinstance(metadata, dict):
            metadata = {}
    except (TypeError, ValueError):
        metadata = {}
    visible = body_visible_to_device(
        metadata,
        None if origin_device_id is None else str(origin_device_id),
        None if viewer_device_id is None else str(viewer_device_id),
    )
    return 1 if visible else 0


def redact_notification_for_device(
    notification: NotificationPublic,
    device_id: str | None,
) -> NotificationPublic:
    if body_visible_to_device(
        notification.metadata,
        notification.origin_device_id,
        device_id,
    ):
        return notification
    if notification.body == PRIVACY_HIDDEN_BODY:
        return notification
    return notification.model_copy(update={"body": PRIVACY_HIDDEN_BODY})


def redact_event_for_device(event: SyncEvent, device_id: str | None) -> SyncEvent:
    if event.notification is None:
        return event
    redacted = redact_notification_for_device(event.notification, device_id)
    if redacted is event.notification:
        return event
    return event.model_copy(update={"notification": redacted})
