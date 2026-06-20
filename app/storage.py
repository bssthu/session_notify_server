from __future__ import annotations

import json
import secrets
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

# 配对码字符集:去掉易混淆的 I/L/O/U/0/1,生成形如 7Q4K-9XKM 的人类可读码。
_PAIR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


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
    def __init__(
        self,
        db_path: str | Path,
        *,
        access_ttl: timedelta = timedelta(hours=1),
        refresh_ttl: timedelta = timedelta(days=90),
        pair_code_ttl: timedelta = timedelta(seconds=300),
    ) -> None:
        self.db_path = Path(db_path)
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # access 短期、refresh 长期;bind/refresh 时写入 *_expires_at,authenticate/refresh
        # 时校验。老库 migration 后该列为 NULL → 视为不过期(向后兼容,不强制存量重绑)。
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        # 配对码有效期:已绑设备签发,新设备消费后绑定。一次性,过期失效。
        self.pair_code_ttl = pair_code_ttl
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
                    revoked_at TEXT,
                    notifications_enabled INTEGER NOT NULL DEFAULT 1,
                    access_expires_at TEXT,
                    refresh_expires_at TEXT
                );

                CREATE TABLE IF NOT EXISTS pair_codes (
                    code_hash TEXT PRIMARY KEY,
                    issued_by_device_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    consumed_device_id TEXT
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
            self._ensure_device_columns()
            self._ensure_notification_origin_columns()

    def _ensure_device_columns(self) -> None:
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(devices)").fetchall()}
        additions = {
            "notifications_enabled": "INTEGER NOT NULL DEFAULT 1",
            "access_expires_at": "TEXT",
            "refresh_expires_at": "TEXT",
        }
        for name, definition in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE devices ADD COLUMN {name} {definition}")

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
        access_expires_at = created_at + self.access_ttl
        refresh_expires_at = created_at + self.refresh_ttl
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO devices (
                    id, name, platform, refresh_token_hash, access_token_hash,
                    created_at, last_seen_at, revoked_at, notifications_enabled,
                    access_expires_at, refresh_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1, ?, ?)
                """,
                (
                    device_id,
                    name,
                    platform.value,
                    sha256_text(refresh_token),
                    sha256_text(access_token),
                    _dt(created_at),
                    _dt(created_at),
                    _dt(access_expires_at),
                    _dt(refresh_expires_at),
                ),
            )
        return DeviceBindResponse(
            device=DevicePublic(
                id=device_id,
                name=name,
                platform=platform,
                created_at=created_at,
                last_seen_at=created_at,
                notifications_enabled=True,
            ),
            refresh_token=refresh_token,
            access_token=access_token,
            access_expires_at=access_expires_at,
        )

    def rebind_device(self, refresh_token: str, name: str, platform: DevicePlatform) -> DeviceBindResponse | None:
        """strict 模式下本机重新绑定:用旧 refresh_token 证明身份,换发全新 token(轮换 refresh)。
        保留 device_id(同一台设备)、原 notifications_enabled 与 created_at,更新 name/platform/过期。
        旧 token 无效/过期/已撤销返回 None(调用方回退到配对码/重置)。"""
        token_hash = sha256_text(refresh_token)
        now = utc_now()
        new_refresh = new_token("sn_refresh")
        new_access = new_token("sn_access")
        access_expires_at = now + self.access_ttl
        refresh_expires_at = now + self.refresh_ttl
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, created_at, notifications_enabled FROM devices
                WHERE refresh_token_hash = ? AND revoked_at IS NULL
                  AND (refresh_expires_at IS NULL OR refresh_expires_at > ?)
                """,
                (token_hash, _dt(now)),
            ).fetchone()
            if row is None:
                return None
            device_id = row["id"]
            created_at = _parse_dt(row["created_at"]) or now
            notifications_enabled = bool(row["notifications_enabled"])
            self._conn.execute(
                """
                UPDATE devices
                SET name = ?, platform = ?, refresh_token_hash = ?, access_token_hash = ?,
                    access_expires_at = ?, refresh_expires_at = ?, last_seen_at = ?
                WHERE id = ?
                """,
                (name, platform.value, sha256_text(new_refresh), sha256_text(new_access),
                 _dt(access_expires_at), _dt(refresh_expires_at), _dt(now), device_id),
            )
        return DeviceBindResponse(
            device=DevicePublic(
                id=device_id,
                name=name,
                platform=platform,
                created_at=created_at,
                last_seen_at=now,
                notifications_enabled=notifications_enabled,
            ),
            refresh_token=new_refresh,
            access_token=new_access,
            access_expires_at=access_expires_at,
        )

    def revoke_all_devices(self) -> int:
        """撤销所有未撤销设备,回到 bootstrap 态。供 localhost-only 的 reset 端点用。返回撤销数。"""
        now = utc_now()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE revoked_at IS NULL",
                (_dt(now),),
            )
        return cursor.rowcount

    def list_devices(self) -> list[DevicePublic]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled
                FROM devices
                WHERE revoked_at IS NULL
                ORDER BY created_at ASC
                """
            ).fetchall()
        return [self._device_from_row(row) for row in rows]

    def update_device(
        self,
        device_id: str,
        *,
        name: str | None = None,
        notifications_enabled: bool | None = None,
    ) -> DevicePublic:
        values: list[Any] = []
        assignments: list[str] = []
        if name is not None:
            cleaned = name.strip()
            if not cleaned:
                raise ValueError("Device name is required.")
            assignments.append("name = ?")
            values.append(cleaned)
        if notifications_enabled is not None:
            assignments.append("notifications_enabled = ?")
            values.append(1 if notifications_enabled else 0)

        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled
                FROM devices
                WHERE id = ? AND revoked_at IS NULL
                """,
                (device_id,),
            ).fetchone()
            if row is None:
                raise KeyError(device_id)
            if assignments:
                self._conn.execute(
                    f"UPDATE devices SET {', '.join(assignments)} WHERE id = ?",
                    (*values, device_id),
                )
                row = self._conn.execute(
                    """
                    SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled
                    FROM devices
                    WHERE id = ?
                    """,
                    (device_id,),
                ).fetchone()
        return self._device_from_row(row)

    def revoke_device(self, device_id: str) -> DevicePublic:
        revoked_at = utc_now()
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled
                FROM devices
                WHERE id = ?
                """,
                (device_id,),
            ).fetchone()
            if row is None or row["revoked_at"] is not None:
                raise KeyError(device_id)
            self._conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE id = ?",
                (_dt(revoked_at), device_id),
            )
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled
                FROM devices
                WHERE id = ?
                """,
                (device_id,),
            ).fetchone()
        return self._device_from_row(row)

    def has_any_device(self) -> bool:
        """是否存在未撤销的已绑设备。strict 模式下据此判断:已有设备时裸 bind 被拒。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM devices WHERE revoked_at IS NULL LIMIT 1"
            ).fetchone()
        return row is not None

    def issue_pair_code(self, device: DevicePublic) -> tuple[str, datetime]:
        """已绑设备签发一个一次性配对码(默认 5 分钟有效)。明文码不落库,只存哈希。"""
        created_at = utc_now()
        expires_at = created_at + self.pair_code_ttl
        code = "{}-{}".format(
            "".join(secrets.choice(_PAIR_ALPHABET) for _ in range(4)),
            "".join(secrets.choice(_PAIR_ALPHABET) for _ in range(4)),
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO pair_codes (code_hash, issued_by_device_id, created_at, expires_at, consumed_at, consumed_device_id)
                VALUES (?, ?, ?, ?, NULL, NULL)
                """,
                (sha256_text(code), device.id, _dt(created_at), _dt(expires_at)),
            )
        return code, expires_at

    def consume_pair_code(self, code: str, name: str, platform: DevicePlatform) -> DeviceBindResponse | None:
        """消费配对码 → 复用 bind_device 绑定新设备。无效/过期/已用返回 None(一次性)。"""
        code_hash = sha256_text(code)
        now = utc_now()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT code_hash, expires_at, consumed_at FROM pair_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
            if row is None or row["consumed_at"] is not None:
                return None
            if (_parse_dt(row["expires_at"]) or now) <= now:
                return None
            # 先标记消费防并发重复使用,再在锁外执行 bind_device(它自带锁)。
            self._conn.execute(
                "UPDATE pair_codes SET consumed_at = ? WHERE code_hash = ?",
                (_dt(now), code_hash),
            )
        response = self.bind_device(name, platform)
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE pair_codes SET consumed_device_id = ? WHERE code_hash = ?",
                (response.device.id, code_hash),
            )
        return response

    def device_notifications_enabled(self, device_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT notifications_enabled
                FROM devices
                WHERE id = ? AND revoked_at IS NULL
                """,
                (device_id,),
            ).fetchone()
        return bool(row and row["notifications_enabled"])

    def event_for_device(self, event: SyncEvent, device: DevicePublic) -> SyncEvent:
        if event.event_type != EventType.notification_created or device.notifications_enabled:
            return event
        return event.model_copy(update={"notification": None})

    def should_deliver_event_to_device(self, event: SyncEvent, device_id: str) -> bool:
        if event.event_type != EventType.notification_created:
            return True
        return self.device_notifications_enabled(device_id)

    def authenticate(self, access_token: str) -> DevicePublic | None:
        token_hash = sha256_text(access_token)
        now = utc_now()
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled
                FROM devices
                WHERE access_token_hash = ? AND revoked_at IS NULL
                  AND (access_expires_at IS NULL OR access_expires_at > ?)
                """,
                (token_hash, _dt(now)),
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
        access_expires_at = now + self.access_ttl
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled
                FROM devices
                WHERE refresh_token_hash = ? AND revoked_at IS NULL
                  AND (refresh_expires_at IS NULL OR refresh_expires_at > ?)
                """,
                (token_hash, _dt(now)),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                """
                UPDATE devices
                SET access_token_hash = ?, access_expires_at = ?, last_seen_at = ?
                WHERE id = ?
                """,
                (sha256_text(access_token), _dt(access_expires_at), _dt(now), row["id"]),
            )
        return AccessTokenResponse(
            device=self._device_from_row(row, last_seen_at=now),
            access_token=access_token,
            access_expires_at=access_expires_at,
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

    def acknowledge_pending_permissions_for_session(
        self,
        *,
        source: str,
        session_id: str | None,
        device_id: str,
        reason: str,
    ) -> list[SyncEvent]:
        """会话级兜底清理:把同一 (source, session_id) 下所有 active 的 permission
        request 置为 acknowledged。不依赖 command 配对键,覆盖 PostToolUse 不会到达的
        场景(用户在 CLI 拒绝权限、会话中断、配对失败)。由调用方在会话结束类 hook
        (Stop/TaskCompleted/StopFailure/SubagentStop)到达时触发。

        与 resolve_pending_permission 的区别:那是按 command 精确配对、命中最近一条;
        本方法是按会话批量兜底。device_id 为真实 current_device,写 acks 外键合法。
        返回每个被清理通知的 notification.acknowledged 事件,供调用方逐条广播。
        """
        now = utc_now()
        target_session = session_id or "local"
        events: list[SyncEvent] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                """
                SELECT * FROM notifications
                WHERE status = ? AND source = ?
                """,
                (NotificationStatus.active.value, source),
            ).fetchall()
            for row in rows:
                notification = self._notification_from_row(row)
                if notification.session_id != target_session:
                    continue
                # approval 类(needs confirmation)都清理:claude 一次权限请求会产生
                # PermissionRequest 与 Notification(permission_prompt) 两条通知,
                # 二者都要在会话结束时清掉,否则任一残留都会被重启 reload 重显。
                if "needs confirmation" not in (notification.title or "").lower():
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
                events.append(
                    self._append_event(
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
                )
        return events

    def events_after(self, since_event_id: str | None, device: DevicePublic | None = None) -> list[SyncEvent]:
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
        events = [SyncEvent.model_validate_json(row["payload"]) for row in rows]
        if device is None:
            return events
        return [self.event_for_device(event, device) for event in events]

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

    def acknowledge_legacy_permission_requests(self, reason: str = "migration_cleanup") -> list[SyncEvent]:
        """一次性迁移:把所有 active 且 hook_event_name=permissionrequest 的历史残留
        置为 acknowledged。幂等 —— 只动 status=active 的。用于 resolve 机制(main.py
        d67e95d, 2026-06-19)上线前的历史堆积,避免它们在客户端重启时 reload 重显。

        不写 acks 表:acks 有 device_id REFERENCES devices(id) 外键 + PRAGMA
        foreign_keys=ON,迁移时无真实设备上下文,写入会违反外键。仅 UPDATE status
        + 追加 notification.acknowledged 事件(ack_by_device_id=None),返回供启动广播。
        """
        now = utc_now()
        events: list[SyncEvent] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT id, title, metadata FROM notifications WHERE status = ?",
                (NotificationStatus.active.value,),
            ).fetchall()
            for row in rows:
                # approval 类(needs confirmation)都清理(PermissionRequest 与 Notification
                # permission_prompt 两类);但仅限 hook 来源,排除用户手动创建的同名通知。
                if "needs confirmation" not in (row["title"] or "").lower():
                    continue
                try:
                    metadata = json.loads(row["metadata"]) if row["metadata"] else {}
                except (TypeError, ValueError):
                    metadata = {}
                if not metadata.get("hook_event_name"):
                    continue
                self._conn.execute(
                    """
                    UPDATE notifications
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (NotificationStatus.acknowledged.value, _dt(now), row["id"]),
                )
                events.append(
                    self._append_event(
                        SyncEvent(
                            event_id=new_id(),
                            event_type=EventType.notification_acknowledged,
                            created_at=now,
                            notification_id=row["id"],
                            ack_by_device_id=None,
                            ack_at=now,
                            reason=reason,
                        )
                    )
                )
        return events

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
            notifications_enabled=bool(row["notifications_enabled"]),
        )
