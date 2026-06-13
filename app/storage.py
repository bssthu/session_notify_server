from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timezone
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

    def create_notification(self, request: NotificationCreate) -> tuple[NotificationPublic, SyncEvent]:
        now = utc_now()
        notification = NotificationPublic(
            id=new_id(),
            source=request.source,
            session_id=request.session_id,
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

    def _insert_notification(self, notification: NotificationPublic) -> None:
        self._conn.execute(
            """
            INSERT INTO notifications (
                id, source, session_id, title, body, level, status,
                created_at, updated_at, expires_at, requires_ack, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                notification.id,
                notification.source,
                notification.session_id,
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
