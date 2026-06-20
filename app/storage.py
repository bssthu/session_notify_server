from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .schemas import (
    AckResponse,
    AccessTokenResponse,
    DeviceBindResponse,
    DevicePlatform,
    DevicePublic,
    EventType,
    NotificationCreate,
    NotificationLevel,
    NotificationPublic,
    NotificationStatus,
    SCHEMA_VERSION,
    SyncEvent,
    new_id,
    utc_now,
)
from .security import new_token, sha256_text


def _dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value).astimezone(timezone.utc)


# 与客户端 hookResolutionKey(notification-logic.js)/rawToolCommand 等价的配对键。
# 关键:command 必须从 metadata.raw 取 —— incoming(payload 经 _hook_metadata)与
# stored(notification.metadata)的 raw 同源(同一份 bridge metadata.raw),保证两端
# 一致;若改用顶层 payload.command(bridge 已 FormatSummary 50+50 截断)会与 raw
# (TrimLongStrings 截断)不一致,长命令配对失败。
def _hook_resolution_key(*, source: str, session_id: str | None, metadata: Any) -> str:
    meta = metadata if isinstance(metadata, dict) else {}
    raw = meta.get("raw") if isinstance(meta.get("raw"), dict) else {}

    def norm(value: Any) -> str:
        return str(value or "").strip().lower()

    cwd = norm(meta.get("cwd")) or norm(raw.get("cwd"))
    tool_name = (
        norm(meta.get("tool_name")) or norm(meta.get("toolName"))
        or norm(raw.get("tool_name")) or norm(raw.get("toolName"))
    )
    # rawToolCommand 顺序:metadata.command → raw.command → tool_input.command
    command = (
        norm(meta.get("command"))
        or norm(raw.get("command"))
        or norm((raw.get("tool_input") or {}).get("command"))
        or norm((meta.get("tool_input") or {}).get("command"))
    )
    return "".join([
        norm(source) or "session",
        norm(session_id) or "local",
        cwd,
        tool_name,
        command,
    ])


class Storage:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    refresh_token_hash TEXT NOT NULL UNIQUE,
                    access_token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    revoked_at TEXT
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    origin_device_id TEXT,
                    origin_device_name TEXT,
                    origin_device_platform TEXT,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT,
                    requires_ack INTEGER NOT NULL,
                    metadata TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    schema_version INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS acks (
                    notification_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    ack_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY(notification_id, device_id),
                    FOREIGN KEY(notification_id) REFERENCES notifications(id),
                    FOREIGN KEY(device_id) REFERENCES devices(id)
                );
                """
            )
            self._ensure_notification_origin_columns()

    def _ensure_notification_origin_columns(self) -> None:
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(notifications)").fetchall()}
        additions = {
            "origin_device_id": "TEXT",
            "origin_device_name": "TEXT",
            "origin_device_platform": "TEXT",
        }
        for name, definition in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE notifications ADD COLUMN {name} {definition}")

    def bind_device(self, name: str, platform: DevicePlatform) -> DeviceBindResponse:
        created_at = utc_now()
        device_id = new_id()
        refresh_token = new_token("sn_refresh")
        access_token = new_token("sn_access")
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO devices (
                    id, name, platform, refresh_token_hash, access_token_hash,
                    created_at, last_seen_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    device_id,
                    name,
                    platform.value,
                    sha256_text(refresh_token),
                    sha256_text(access_token),
                    _dt(created_at),
                    _dt(created_at),
                ),
            )
        return DeviceBindResponse(
            device=DevicePublic(
                id=device_id,
                name=name,
                platform=platform,
                created_at=created_at,
                last_seen_at=created_at,
            ),
            refresh_token=refresh_token,
            access_token=access_token,
        )

    def authenticate(self, access_token: str) -> DevicePublic | None:
        token_hash = sha256_text(access_token)
        now = utc_now()
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at
                FROM devices
                WHERE access_token_hash = ? AND revoked_at IS NULL
                """,
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE devices SET last_seen_at = ? WHERE id = ?",
                (_dt(now), row["id"]),
            )
        return self._device_from_row(row, last_seen_at=now)

    def refresh_access_token(self, refresh_token: str) -> AccessTokenResponse | None:
        token_hash = sha256_text(refresh_token)
        now = utc_now()
        access_token = new_token("sn_access")
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at
                FROM devices
                WHERE refresh_token_hash = ? AND revoked_at IS NULL
                """,
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                """
                UPDATE devices
                SET access_token_hash = ?, last_seen_at = ?
                WHERE id = ?
                """,
                (sha256_text(access_token), _dt(now), row["id"]),
            )
        return AccessTokenResponse(
            device=self._device_from_row(row, last_seen_at=now),
            access_token=access_token,
        )

    def create_notification(
        self,
        request: NotificationCreate,
        origin_device: DevicePublic | None = None,
    ) -> tuple[NotificationPublic, SyncEvent]:
        now = utc_now()
        notification = NotificationPublic(
            id=new_id(),
            source=request.source,
            session_id=request.session_id,
            origin_device_id=origin_device.id if origin_device else None,
            origin_device_name=origin_device.name if origin_device else None,
            origin_device_platform=origin_device.platform if origin_device else None,
            title=request.title,
            body=request.body,
            level=request.level,
            status=NotificationStatus.active,
            created_at=now,
            updated_at=now,
            expires_at=request.expires_at,
            requires_ack=request.requires_ack,
            metadata=request.metadata,
        )
        with self._lock, self._conn:
            self._insert_notification(notification)
            event = self._append_event(
                SyncEvent(
                    event_id=new_id(),
                    event_type=EventType.notification_created,
                    created_at=now,
                    notification=notification,
                )
            )
        return notification, event

    def list_notifications(
        self,
        statuses: Iterable[NotificationStatus] | None = None,
    ) -> list[NotificationPublic]:
        self.expire_due_notifications()
        query = "SELECT * FROM notifications"
        values: list[Any] = []
        if statuses:
            status_values = [status.value for status in statuses]
            query += f" WHERE status IN ({','.join('?' for _ in status_values)})"
            values.extend(status_values)
        query += " ORDER BY created_at ASC"
        with self._lock:
            rows = self._conn.execute(query, values).fetchall()
        return [self._notification_from_row(row) for row in rows]

    def acknowledge(
        self,
        notification_id: str,
        device_id: str,
        reason: str,
    ) -> tuple[AckResponse, SyncEvent | None]:
        now = utc_now()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT * FROM notifications WHERE id = ?",
                (notification_id,),
            ).fetchone()
            if row is None:
                raise KeyError(notification_id)

            notification = self._notification_from_row(row)
            already_acknowledged = notification.status == NotificationStatus.acknowledged

            self._conn.execute(
                """
                INSERT OR IGNORE INTO acks(notification_id, device_id, ack_at, reason)
                VALUES (?, ?, ?, ?)
                """,
                (notification_id, device_id, _dt(now), reason),
            )

            event: SyncEvent | None = None
            if not already_acknowledged:
                self._conn.execute(
                    """
                    UPDATE notifications
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (NotificationStatus.acknowledged.value, _dt(now), notification_id),
                )
                notification = notification.model_copy(
                    update={"status": NotificationStatus.acknowledged, "updated_at": now}
                )
                event = self._append_event(
                    SyncEvent(
                        event_id=new_id(),
                        event_type=EventType.notification_acknowledged,
                        created_at=now,
                        notification_id=notification_id,
                        ack_by_device_id=device_id,
                        ack_at=now,
                        reason=reason,
                    )
                )

        return AckResponse(notification=notification, already_acknowledged=already_acknowledged), event

    def resolve_pending_permission(
        self,
        *,
        source: str,
        session_id: str | None,
        metadata: dict[str, Any],
        device_id: str,
        reason: str,
    ) -> SyncEvent | None:
        """PostToolUse 到达时,按配对键 resolve 最近一条匹配的活跃 permission request。

        与客户端 hookResolutionKey 等价(见 _hook_resolution_key):command 从 metadata.raw
        取,incoming 与 stored 同源。无匹配返回 None(静默 no-op)。命中最近一条
        (ORDER BY created_at DESC 首条):写 acks、置 acknowledged、追加
        notification.acknowledged 事件并返回,供调用方广播。
        """
        incoming_key = _hook_resolution_key(source=source, session_id=session_id, metadata=metadata)
        now = utc_now()
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT * FROM notifications WHERE status = ? ORDER BY created_at DESC",
                (NotificationStatus.active.value,),
            ).fetchall()
            for row in rows:
                notification = self._notification_from_row(row)
                meta = notification.metadata or {}
                if str(meta.get("hook_event_name") or "").lower() != "permissionrequest":
                    continue
                stored_key = _hook_resolution_key(
                    source=notification.source,
                    session_id=notification.session_id,
                    metadata=meta,
                )
                if stored_key != incoming_key:
                    continue
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO acks(notification_id, device_id, ack_at, reason)
                    VALUES (?, ?, ?, ?)
                    """,
                    (notification.id, device_id, _dt(now), reason),
                )
                self._conn.execute(
                    """
                    UPDATE notifications
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (NotificationStatus.acknowledged.value, _dt(now), notification.id),
                )
                return self._append_event(
                    SyncEvent(
                        event_id=new_id(),
                        event_type=EventType.notification_acknowledged,
                        created_at=now,
                        notification_id=notification.id,
                        ack_by_device_id=device_id,
                        ack_at=now,
                        reason=reason,
                    )
                )
        return None

    def events_after(self, since_event_id: str | None) -> list[SyncEvent]:
        values: tuple[Any, ...]
        where = ""
        if since_event_id:
            with self._lock:
                row = self._conn.execute(
                    "SELECT seq FROM events WHERE id = ?",
                    (since_event_id,),
                ).fetchone()
            if row is None:
                where = ""
                values = ()
            else:
                where = "WHERE seq > ?"
                values = (row["seq"],)
        else:
            values = ()
        with self._lock:
            rows = self._conn.execute(
                f"SELECT payload FROM events {where} ORDER BY seq ASC",
                values,
            ).fetchall()
        return [SyncEvent.model_validate_json(row["payload"]) for row in rows]

    def expire_due_notifications(self) -> list[SyncEvent]:
        now = utc_now()
        with self._lock, self._conn:
            rows = self._conn.execute(
                """
                SELECT * FROM notifications
                WHERE status = ? AND expires_at IS NOT NULL AND expires_at <= ?
                """,
                (NotificationStatus.active.value, _dt(now)),
            ).fetchall()
            events: list[SyncEvent] = []
            for row in rows:
                notification_id = row["id"]
                self._conn.execute(
                    "UPDATE notifications SET status = ?, updated_at = ? WHERE id = ?",
                    (NotificationStatus.expired.value, _dt(now), notification_id),
                )
                events.append(
                    self._append_event(
                        SyncEvent(
                            event_id=new_id(),
                            event_type=EventType.notification_expired,
                            created_at=now,
                            notification_id=notification_id,
                        )
                    )
                )
        return events

    def backfill_hook_expiry(self, ttl: timedelta) -> int:
        """幂等回填:给 expires_at 为空且属于 hook 来源(metadata.hook_event_name 非空)
        的通知补上 expires_at = created_at + ttl。用于一次性兼容历史数据(创建于 TTL 上线前)。
        仅改 expires_at IS NULL 的,已设过的不动。返回回填行数。
        """
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT id, created_at, metadata FROM notifications WHERE expires_at IS NULL"
            ).fetchall()
            count = 0
            for row in rows:
                try:
                    metadata = json.loads(row["metadata"])
                except (TypeError, ValueError):
                    continue
                if not metadata.get("hook_event_name"):
                    continue
                created = _parse_dt(row["created_at"])
                if created is None:
                    continue
                self._conn.execute(
                    "UPDATE notifications SET expires_at = ? WHERE id = ?",
                    (_dt(created + ttl), row["id"]),
                )
                count += 1
        return count

    def _insert_notification(self, notification: NotificationPublic) -> None:
        self._conn.execute(
            """
            INSERT INTO notifications (
                id, source, session_id, origin_device_id, origin_device_name,
                origin_device_platform, title, body, level, status,
                created_at, updated_at, expires_at, requires_ack, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                notification.id,
                notification.source,
                notification.session_id,
                notification.origin_device_id,
                notification.origin_device_name,
                notification.origin_device_platform.value if notification.origin_device_platform else None,
                notification.title,
                notification.body,
                notification.level.value,
                notification.status.value,
                _dt(notification.created_at),
                _dt(notification.updated_at),
                _dt(notification.expires_at) if notification.expires_at else None,
                1 if notification.requires_ack else 0,
                json.dumps(notification.metadata, ensure_ascii=False, sort_keys=True),
            ),
        )

    def _append_event(self, event: SyncEvent) -> SyncEvent:
        self._conn.execute(
            """
            INSERT INTO events(id, schema_version, type, payload, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                SCHEMA_VERSION,
                event.event_type.value,
                event.model_dump_json(),
                _dt(event.created_at),
            ),
        )
        return event

    def _notification_from_row(self, row: sqlite3.Row) -> NotificationPublic:
        return NotificationPublic(
            id=row["id"],
            source=row["source"],
            session_id=row["session_id"],
            origin_device_id=row["origin_device_id"],
            origin_device_name=row["origin_device_name"],
            origin_device_platform=DevicePlatform(row["origin_device_platform"]) if row["origin_device_platform"] else None,
            title=row["title"],
            body=row["body"],
            level=NotificationLevel(row["level"]),
            status=NotificationStatus(row["status"]),
            created_at=_parse_dt(row["created_at"]) or utc_now(),
            updated_at=_parse_dt(row["updated_at"]) or utc_now(),
            expires_at=_parse_dt(row["expires_at"]),
            requires_ack=bool(row["requires_ack"]),
            metadata=json.loads(row["metadata"]),
        )

    def _device_from_row(self, row: sqlite3.Row, last_seen_at: datetime | None = None) -> DevicePublic:
        return DevicePublic(
            id=row["id"],
            name=row["name"],
            platform=DevicePlatform(row["platform"]),
            created_at=_parse_dt(row["created_at"]) or utc_now(),
            last_seen_at=last_seen_at or _parse_dt(row["last_seen_at"]),
            revoked_at=_parse_dt(row["revoked_at"]),
        )
