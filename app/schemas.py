from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


SCHEMA_VERSION = 1


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid4())


class DevicePlatform(StrEnum):
    windows = "windows"
    android = "android"


class NotificationLevel(StrEnum):
    info = "info"
    success = "success"
    important = "important"
    critical = "critical"


class NotificationStatus(StrEnum):
    active = "active"
    acknowledged = "acknowledged"
    expired = "expired"
    cancelled = "cancelled"


class EventType(StrEnum):
    notification_created = "notification.created"
    notification_acknowledged = "notification.acknowledged"
    notification_expired = "notification.expired"


class DeviceBindRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    platform: DevicePlatform


class DevicePublic(BaseModel):
    id: str
    name: str
    platform: DevicePlatform
    created_at: datetime
    last_seen_at: datetime | None = None
    revoked_at: datetime | None = None


class DeviceBindResponse(BaseModel):
    device: DevicePublic
    refresh_token: str
    access_token: str
    token_type: Literal["bearer"] = "bearer"


class TokenRefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class AccessTokenResponse(BaseModel):
    device: DevicePublic
    access_token: str
    token_type: Literal["bearer"] = "bearer"


class NotificationCreate(BaseModel):
    source: str = Field(min_length=1, max_length=40)
    session_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=2000)
    level: NotificationLevel = NotificationLevel.info
    expires_at: datetime | None = None
    requires_ack: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("expires_at")
    @classmethod
    def ensure_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class NotificationPublic(BaseModel):
    id: str
    source: str
    session_id: str
    title: str
    body: str
    level: NotificationLevel
    status: NotificationStatus
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    requires_ack: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class AckRequest(BaseModel):
    reason: str = Field(default="user_confirmed", min_length=1, max_length=80)


class AckResponse(BaseModel):
    notification: NotificationPublic
    already_acknowledged: bool


class SyncEvent(BaseModel):
    schema_version: Literal[1] = SCHEMA_VERSION
    event_id: str
    event_type: EventType
    created_at: datetime
    notification: NotificationPublic | None = None
    notification_id: str | None = None
    ack_by_device_id: str | None = None
    ack_at: datetime | None = None
    reason: str | None = None


class EventsResponse(BaseModel):
    events: list[SyncEvent]


class HookPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_type: str | None = None
    hook_event_name: str | None = None
    hook_status: str | None = None
    notification_type: str | None = None
    title: str | None = None
    message: str | None = None
    prompt: str | None = None
    command: str | None = None
    summary: str | None = None
    last_assistant_message: str | None = None
    session_id: str | None = None
    cwd: str | None = None
    transcript_path: str | None = None
    tool_name: str | None = None
    tool_input: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
