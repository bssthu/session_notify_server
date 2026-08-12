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
    DevicePresenceSummary,
    DevicePublic,
    DeviceSessionState,
    EventType,
    NotificationCreate,
    NotificationHistoryFilterOptions,
    NotificationHistoryMachineOption,
    NotificationLevel,
    NotificationPublic,
    NotificationStatus,
    SCHEMA_VERSION,
    SyncEvent,
    WindowsDevicePresence,
    new_id,
    utc_now,
)
from .hook_policy import is_codex_permission_request, is_noise_hook_event
from .security import new_token, sha256_text

# 配对码字符集:去掉易混淆的 I/L/O/U/0/1,生成形如 7Q4K-9XKM 的人类可读码。
_PAIR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_HISTORY_MACHINE_OPTION_LIMIT = 100
_HISTORY_AGENT_OPTION_LIMIT = 50
_HISTORY_TAG_OPTION_LIMIT = 100


def _dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _metadata_bool(metadata: dict[str, Any], *keys: str) -> bool:
    for key in keys:
        if key not in metadata:
            continue
        value = metadata[key]
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() == "true"
    return False


def _notification_visible_for_history(
    source: object,
    title: object,
    metadata_json: object,
    suppress_codex_permission_requests: object,
) -> int:
    """SQLite UDF matching Windows notification visibility without returning hidden rows."""
    try:
        metadata = json.loads(str(metadata_json or "{}"))
        if not isinstance(metadata, dict):
            metadata = {}
    except (TypeError, ValueError):
        metadata = {}
    source_lower = str(source or "").lower()
    title_lower = str(title or "").lower()
    event_name = str(
        metadata.get("hook_event_name")
        or metadata.get("hookEventName")
        or metadata.get("hook_event_type")
        or metadata.get("hookEventType")
        or ""
    ).lower()
    notification_type = str(
        metadata.get("notification_type") or metadata.get("notificationType") or ""
    ).lower()
    hook_status = str(metadata.get("hook_status") or metadata.get("hookStatus") or "").lower()
    raw_event_type = str(
        metadata.get("raw_event_type") or metadata.get("rawEventType") or ""
    ).lower()
    is_hook = (
        source_lower in ("claude", "codex")
        or bool(event_name)
        or bool(notification_type)
        or bool(hook_status)
        or bool(raw_event_type)
        or bool(metadata.get("source_tool") or metadata.get("sourceTool"))
    )
    if not is_hook:
        return 1
    raw = metadata.get("raw")
    if is_noise_hook_event(
        source=source_lower,
        event_name=event_name or raw_event_type,
        notification_type=" ".join((notification_type, raw_event_type)),
        hook_status=hook_status,
        title=title_lower,
        body_generated=_metadata_bool(metadata, "body_generated", "bodyGenerated"),
        cwd=str(metadata.get("cwd") or ""),
        transcript_path=str(metadata.get("transcript_path") or metadata.get("transcriptPath") or ""),
        permission_mode=str(metadata.get("permission_mode") or metadata.get("permissionMode") or ""),
        raw=raw if isinstance(raw, dict) else None,
    ):
        return 0
    if bool(suppress_codex_permission_requests) and is_codex_permission_request(
        source=source_lower,
        event_name=event_name,
        notification_type=notification_type,
        hook_status=hook_status,
        title=title_lower,
        raw_event_type=raw_event_type,
    ):
        return 0
    return 1


def _history_option_text(value: object, max_length: int) -> str:
    raw = ("" if value is None else str(value))[:4096]
    normalized: list[str] = []
    pending_space = False
    for character in raw:
        code_point = ord(character)
        unsafe_format = (
            code_point in (0x00AD, 0x061C, 0x180E, 0xFEFF)
            or 0x200B <= code_point <= 0x200F
            or 0x202A <= code_point <= 0x202E
            or 0x2060 <= code_point <= 0x206F
        )
        control = (
            code_point <= 0x1F
            or 0x7F <= code_point <= 0x9F
            or code_point in (0x2028, 0x2029)
        )
        if unsafe_format:
            continue
        if control or character.isspace():
            pending_space = bool(normalized)
            continue
        if pending_space:
            normalized.append(" ")
            pending_space = False
        normalized.append(character)
    text = "".join(normalized)
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 1]}…"


def _notification_tag_for_filter(metadata_json: object) -> str:
    """Return the scalar notification tag used by history text filters."""
    try:
        metadata = json.loads(str(metadata_json or "{}"))
        if not isinstance(metadata, dict):
            return ""
    except (TypeError, ValueError):
        return ""
    for key in ("tag", "session_notify_tag", "sessionNotifyTag"):
        value = metadata.get(key)
        if isinstance(value, str):
            return _history_option_text(value, 120)
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return _history_option_text(value, 120)
    return ""


def _history_contains_pattern(value: str | None) -> str | None:
    """Build a literal SQLite LIKE contains-pattern with wildcard escaping."""
    normalized = str(value or "").strip()
    if not normalized:
        return None
    escaped = normalized.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# 与客户端 hookResolutionIdentity(notification-logic.js)/rawToolCommand 等价的基础
# 配对键。turn_id 单独返回给 resolve_pending_permission 做兼容与歧义判断，不能简单
# 拼接后继续“取最新一条”，否则旧 Bridge/历史通知缺少 turn_id 时无法安全回退。
#
# 关键:command 必须优先从 metadata.raw 取 —— incoming(payload 经 _hook_metadata)与
# stored(notification.metadata)的 raw 同源(同一份 bridge metadata.raw),保证两端
# 一致;顶层 payload.command 已被 Bridge FormatSummary 截断，仅作旧数据兜底。
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
    # rawToolCommand 顺序:raw.command → raw.tool_input.command → metadata 兜底。
    command = (
        norm(raw.get("command"))
        or norm((raw.get("tool_input") or {}).get("command"))
        or norm((raw.get("toolInput") or {}).get("command"))
        or norm(meta.get("command"))
        or norm((meta.get("tool_input") or {}).get("command"))
        or norm((meta.get("toolInput") or {}).get("command"))
    )
    return "".join([
        norm(source) or "session",
        norm(session_id) or "local",
        cwd,
        tool_name,
        command,
    ])


def _hook_turn_id(metadata: Any) -> str:
    meta = metadata if isinstance(metadata, dict) else {}
    raw = meta.get("raw") if isinstance(meta.get("raw"), dict) else {}
    value = (
        meta.get("turn_id")
        or meta.get("turnId")
        or raw.get("turn_id")
        or raw.get("turnId")
    )
    # turn_id 是不透明标识符，只去除边缘空白，不做大小写归一化。
    return str(value or "").strip()


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
        self._conn.create_function(
            "notification_visible_for_history",
            4,
            _notification_visible_for_history,
            deterministic=True,
        )
        self._conn.create_function(
            "notification_tag_for_filter",
            1,
            _notification_tag_for_filter,
            deterministic=True,
        )
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
                    notification_pause_until TEXT,
                    session_state TEXT NOT NULL DEFAULT 'unknown',
                    session_state_updated_at TEXT,
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
                    dedupe_key TEXT,
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

                CREATE INDEX IF NOT EXISTS idx_notifications_created_id
                ON notifications(created_at DESC, id DESC);

                CREATE INDEX IF NOT EXISTS idx_notifications_status_created_id
                ON notifications(status, created_at DESC, id DESC);
                """
            )
            self._ensure_device_columns()
            self._ensure_notification_origin_columns()
            self._ensure_notification_dedupe_column()

    def _ensure_device_columns(self) -> None:
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(devices)").fetchall()}
        additions = {
            "notifications_enabled": "INTEGER NOT NULL DEFAULT 1",
            "notification_pause_until": "TEXT",
            "session_state": "TEXT NOT NULL DEFAULT 'unknown'",
            "session_state_updated_at": "TEXT",
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

    def _ensure_notification_dedupe_column(self) -> None:
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(notifications)").fetchall()}
        if "dedupe_key" not in columns:
            self._conn.execute("ALTER TABLE notifications ADD COLUMN dedupe_key TEXT")
        # SQLite UNIQUE indexes allow multiple NULL values. Only notifications with an
        # explicit cross-ingest identity participate in de-duplication.
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedupe_key "
            "ON notifications(dedupe_key)"
        )

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
                    access_expires_at = ?, refresh_expires_at = ?, last_seen_at = ?,
                    session_state = 'unknown', session_state_updated_at = NULL,
                    notification_pause_until = NULL
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
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
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
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
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
                    SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                           notification_pause_until, session_state, session_state_updated_at
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
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
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
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
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

    def update_device_session_state(
        self,
        device_id: str,
        session_state: DeviceSessionState,
        *,
        notification_pause_until: datetime | None,
        stale_after: timedelta,
    ) -> tuple[DevicePublic, bool]:
        """Store a Windows heartbeat and indicate whether effective availability changed."""
        now = utc_now()
        stale_before = now - stale_after
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
                FROM devices
                WHERE id = ? AND revoked_at IS NULL
                """,
                (device_id,),
            ).fetchone()
            if row is None:
                raise KeyError(device_id)
            if DevicePlatform(row["platform"]) is not DevicePlatform.windows:
                raise ValueError("Only Windows devices can report a desktop session state")

            previous_updated_at = _parse_dt(row["session_state_updated_at"])
            previous_state = DeviceSessionState(row["session_state"] or DeviceSessionState.unknown.value)
            previous_effective = (
                previous_state
                if previous_updated_at is not None and previous_updated_at >= stale_before
                else DeviceSessionState.unknown
            )
            previous_pause_until = _parse_dt(row["notification_pause_until"])
            previous_pause_active = (
                previous_pause_until is not None and previous_pause_until > now
            )
            next_pause_active = (
                notification_pause_until is not None and notification_pause_until > now
            )
            self._conn.execute(
                """
                UPDATE devices
                SET session_state = ?, session_state_updated_at = ?, notification_pause_until = ?
                WHERE id = ?
                """,
                (
                    session_state.value,
                    _dt(now),
                    _dt(notification_pause_until)
                    if notification_pause_until is not None and notification_pause_until > now
                    else None,
                    device_id,
                ),
            )
            row = self._conn.execute(
                """
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
                FROM devices
                WHERE id = ?
                """,
                (device_id,),
            ).fetchone()
        pause_availability_changed = (
            previous_pause_active != next_pause_active
            # Expired deadlines no longer count as active in the summary, but clearing
            # the stored value is still the first opportunity to wake Android clients
            # after the deadline passed (there is no server-side expiry timer).
            or (previous_pause_until is not None and not next_pause_active)
        )
        return self._device_from_row(row), (
            previous_effective is not session_state or pause_availability_changed
        )

    def device_presence_summary(
        self,
        stale_after: timedelta,
        *,
        now: datetime | None = None,
    ) -> DevicePresenceSummary:
        evaluated_at = now or utc_now()
        stale_before = evaluated_at - stale_after
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, name, notification_pause_until, session_state, session_state_updated_at
                FROM devices
                WHERE platform = ? AND revoked_at IS NULL
                ORDER BY created_at ASC
                """,
                (DevicePlatform.windows.value,),
            ).fetchall()

        windows_devices: list[WindowsDevicePresence] = []
        fresh_windows = 0
        any_unlocked = False
        any_unlocked_unpaused = False
        for row in rows:
            reported = DeviceSessionState(row["session_state"] or DeviceSessionState.unknown.value)
            updated_at = _parse_dt(row["session_state_updated_at"])
            fresh = updated_at is not None and updated_at >= stale_before
            effective = reported if fresh else DeviceSessionState.unknown
            if fresh:
                fresh_windows += 1
            if effective is DeviceSessionState.unlocked:
                any_unlocked = True
                pause_until = _parse_dt(row["notification_pause_until"])
                if pause_until is None or pause_until <= evaluated_at:
                    any_unlocked_unpaused = True
            windows_devices.append(
                WindowsDevicePresence(
                    device_id=row["id"],
                    device_name=row["name"],
                    reported_session_state=reported,
                    effective_session_state=effective,
                    session_state_updated_at=updated_at,
                )
            )
        return DevicePresenceSummary(
            any_unlocked_windows=any_unlocked,
            any_unlocked_unpaused_windows=any_unlocked_unpaused,
            registered_windows=len(windows_devices),
            fresh_windows=fresh_windows,
            evaluated_at=evaluated_at,
            stale_after_seconds=max(1, int(stale_after.total_seconds())),
            windows_devices=windows_devices,
        )

    def is_android_device(self, device_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT platform FROM devices WHERE id = ? AND revoked_at IS NULL",
                (device_id,),
            ).fetchone()
        return bool(row and row["platform"] == DevicePlatform.android.value)

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

    def consume_pair_code(
        self, code: str, name: str, platform: DevicePlatform
    ) -> tuple[DeviceBindResponse, dict] | None:
        """消费配对码 → 复用 bind_device 绑定新设备。无效/过期/已用返回 None(一次性)。

        成功时额外返回配对码元信息(供调用方构造 pair.consumed 推送事件):
        {code_hash, issued_by_device_id, consumed_device_name}。
        """
        code_hash = sha256_text(code)
        now = utc_now()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT code_hash, expires_at, consumed_at, issued_by_device_id FROM pair_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
            if row is None or row["consumed_at"] is not None:
                return None
            if (_parse_dt(row["expires_at"]) or now) <= now:
                return None
            issued_by_device_id = row["issued_by_device_id"]
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
        meta = {
            "code_hash": code_hash,
            "issued_by_device_id": issued_by_device_id,
            "consumed_device_name": response.device.name,
        }
        return response, meta

    def pair_code_status(self, code: str) -> dict | None:
        """按明文码查询配对状态(只读,不消费)。查不到返回 None;
        否则返回 {consumed, expired, consumed_device_name}。
        """
        code_hash = sha256_text(code)
        now = utc_now()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT expires_at, consumed_at, consumed_device_id FROM pair_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
            if row is None:
                return None
            expired = (_parse_dt(row["expires_at"]) or now) <= now
            consumed = row["consumed_at"] is not None
            consumed_device_name = None
            if consumed and row["consumed_device_id"]:
                device = self._conn.execute(
                    "SELECT name FROM devices WHERE id = ?", (row["consumed_device_id"],)
                ).fetchone()
                consumed_device_name = device["name"] if device else None
        return {
            "consumed": consumed,
            "expired": expired,
            "consumed_device_name": consumed_device_name,
        }

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
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
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
                SELECT id, name, platform, created_at, last_seen_at, revoked_at, notifications_enabled,
                       notification_pause_until, session_state, session_state_updated_at
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
        *,
        dedupe_key: str | None = None,
    ) -> tuple[NotificationPublic, SyncEvent | None]:
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
            if dedupe_key:
                existing = self._conn.execute(
                    "SELECT * FROM notifications WHERE dedupe_key = ?",
                    (dedupe_key,),
                ).fetchone()
                if existing is not None:
                    return self._merge_duplicate_notification(existing, notification), None
            try:
                self._insert_notification(notification, dedupe_key=dedupe_key)
            except sqlite3.IntegrityError:
                # A second server process can win the unique-key race after the lookup.
                # Only recover when this exact de-duplication key now exists.
                if not dedupe_key:
                    raise
                existing = self._conn.execute(
                    "SELECT * FROM notifications WHERE dedupe_key = ?",
                    (dedupe_key,),
                ).fetchone()
                if existing is None:
                    raise
                return self._merge_duplicate_notification(existing, notification), None
            event = self._append_event(
                SyncEvent(
                    event_id=new_id(),
                    event_type=EventType.notification_created,
                    created_at=now,
                    notification=notification,
                )
            )
        return notification, event

    def _merge_duplicate_notification(
        self,
        existing_row: sqlite3.Row,
        incoming: NotificationPublic,
    ) -> NotificationPublic:
        """Persist diagnostic evidence from both transports without creating a second alert."""
        existing = self._notification_from_row(existing_row)
        merged = dict(existing.metadata)
        incoming_meta = incoming.metadata if isinstance(incoming.metadata, dict) else {}
        sources = {
            str(value)
            for value in (
                merged.get("ingest_source"),
                incoming_meta.get("ingest_source"),
                *(merged.get("ingest_sources") or []),
                *(incoming_meta.get("ingest_sources") or []),
            )
            if value
        }
        for key, value in incoming_meta.items():
            if key not in merged and value is not None:
                merged[key] = value
        if sources:
            merged["ingest_sources"] = sorted(sources)
        if "app_server" in sources and "hook_bridge" in sources:
            merged["event_correlation"] = "remote_correlated"
        if merged != existing.metadata:
            now = utc_now()
            self._conn.execute(
                "UPDATE notifications SET metadata = ?, updated_at = ? WHERE id = ?",
                (json.dumps(merged, ensure_ascii=False, sort_keys=True), _dt(now), existing.id),
            )
            existing = existing.model_copy(update={"metadata": merged, "updated_at": now})
        return existing

    def list_notifications(
        self,
        statuses: Iterable[NotificationStatus] | None = None,
        created_since: datetime | None = None,
    ) -> list[NotificationPublic]:
        self.expire_due_notifications()
        query = "SELECT * FROM notifications"
        values: list[Any] = []
        conditions: list[str] = []
        if statuses:
            status_values = [status.value for status in statuses]
            conditions.append(f"status IN ({','.join('?' for _ in status_values)})")
            values.extend(status_values)
        if created_since is not None:
            conditions.append("created_at >= ?")
            values.append(_dt(created_since))
        if conditions:
            query += f" WHERE {' AND '.join(conditions)}"
        query += " ORDER BY created_at ASC"
        with self._lock:
            rows = self._conn.execute(query, values).fetchall()
        return [self._notification_from_row(row) for row in rows]

    def list_recent_notifications(
        self,
        *,
        statuses: Iterable[NotificationStatus] | None,
        created_since: datetime,
        limit: int,
        before_created_at: datetime | None = None,
        before_id: str | None = None,
        visible_only: bool = True,
        suppress_codex_permission_requests: bool = False,
        machine: str | None = None,
        agent: str | None = None,
        tag: str | None = None,
        query_text: str | None = None,
    ) -> tuple[list[NotificationPublic], bool, int, NotificationHistoryFilterOptions]:
        """Return one newest-first history page using a stable (created_at, id) cursor."""
        self.expire_due_notifications()
        conditions = ["created_at >= ?"]
        values: list[Any] = [_dt(created_since)]
        if statuses:
            status_values = [status.value for status in statuses]
            conditions.append(f"status IN ({','.join('?' for _ in status_values)})")
            values.extend(status_values)
        if visible_only:
            conditions.append("notification_visible_for_history(source, title, metadata, ?) = 1")
            values.append(1 if suppress_codex_permission_requests else 0)
        base_conditions = list(conditions)
        base_values = list(values)
        machine_pattern = _history_contains_pattern(machine)
        if machine_pattern is not None:
            conditions.append(
                "(COALESCE(origin_device_name, '') LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR COALESCE(origin_device_id, '') LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR origin_device_id IN ("
                "SELECT id FROM devices WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE))"
            )
            values.extend([machine_pattern, machine_pattern, machine_pattern])
        agent_pattern = _history_contains_pattern(agent)
        if agent_pattern is not None:
            conditions.append("source LIKE ? ESCAPE '\\' COLLATE NOCASE")
            values.append(agent_pattern)
        tag_pattern = _history_contains_pattern(tag)
        if tag_pattern is not None:
            conditions.append("notification_tag_for_filter(metadata) LIKE ? ESCAPE '\\' COLLATE NOCASE")
            values.append(tag_pattern)
        query_pattern = _history_contains_pattern(query_text)
        if query_pattern is not None:
            conditions.append(
                "(title LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR body LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR session_id LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR source LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR COALESCE(origin_device_name, '') LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR COALESCE(origin_device_id, '') LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR origin_device_id IN ("
                "SELECT id FROM devices WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE) "
                "OR notification_tag_for_filter(metadata) LIKE ? ESCAPE '\\' COLLATE NOCASE)"
            )
            values.extend([query_pattern] * 8)

        filter_options = self._recent_notification_filter_options(
            base_conditions,
            base_values,
        )

        where = f" WHERE {' AND '.join(conditions)}"
        with self._lock:
            total_count = int(
                self._conn.execute(
                    f"SELECT COUNT(*) AS count FROM notifications{where}",
                    values,
                ).fetchone()["count"]
            )

        page_conditions = list(conditions)
        page_values = list(values)
        if before_created_at is not None and before_id:
            before_value = _dt(before_created_at)
            page_conditions.append("(created_at < ? OR (created_at = ? AND id < ?))")
            page_values.extend([before_value, before_value, before_id])
        query = f"SELECT * FROM notifications WHERE {' AND '.join(page_conditions)}"
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        page_values.append(limit + 1)
        with self._lock:
            rows = self._conn.execute(query, page_values).fetchall()
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        return (
            [self._notification_from_row(row) for row in page_rows],
            has_more,
            total_count,
            filter_options,
        )

    def _recent_notification_filter_options(
        self,
        conditions: list[str],
        values: list[Any],
    ) -> NotificationHistoryFilterOptions:
        """Return stable suggestions for the current time/status/visibility scope."""
        where = f" WHERE {' AND '.join(conditions)}"
        machine_limit = _HISTORY_MACHINE_OPTION_LIMIT
        agent_limit = _HISTORY_AGENT_OPTION_LIMIT
        tag_limit = _HISTORY_TAG_OPTION_LIMIT
        with self._lock:
            machine_rows = self._conn.execute(
                f"""
                WITH scoped AS (
                    SELECT origin_device_id, origin_device_name
                    FROM notifications{where}
                )
                SELECT
                    NULLIF(TRIM(scoped.origin_device_id), '') AS id,
                    COALESCE(
                        MAX(NULLIF(TRIM(devices.name), '')),
                        MAX(NULLIF(TRIM(scoped.origin_device_name), '')),
                        MAX(NULLIF(TRIM(scoped.origin_device_id), ''))
                    ) AS name
                FROM scoped
                LEFT JOIN devices ON devices.id = scoped.origin_device_id
                WHERE COALESCE(TRIM(scoped.origin_device_id), '') <> ''
                   OR COALESCE(TRIM(scoped.origin_device_name), '') <> ''
                GROUP BY COALESCE(
                    NULLIF(TRIM(scoped.origin_device_id), ''),
                    'name:' || LOWER(TRIM(scoped.origin_device_name))
                )
                ORDER BY name COLLATE NOCASE, id
                LIMIT ?
                """,
                [*values, machine_limit + 1],
            ).fetchall()
            agent_rows = self._conn.execute(
                f"""
                SELECT DISTINCT source AS value
                FROM notifications{where}
                  AND TRIM(source) <> ''
                ORDER BY source COLLATE NOCASE
                LIMIT ?
                """,
                [*values, agent_limit + 1],
            ).fetchall()
            tag_rows = self._conn.execute(
                f"""
                SELECT DISTINCT notification_tag_for_filter(metadata) AS value
                FROM notifications{where}
                  AND notification_tag_for_filter(metadata) <> ''
                ORDER BY value COLLATE NOCASE
                LIMIT ?
                """,
                [*values, tag_limit + 1],
            ).fetchall()

        machines = [
            NotificationHistoryMachineOption(
                id=_history_option_text(row["id"], 120) or None,
                name=_history_option_text(row["name"], 120),
            )
            for row in machine_rows[:machine_limit]
            if _history_option_text(row["name"], 120)
        ]
        agents = list(
            dict.fromkeys(
                text
                for row in agent_rows[:agent_limit]
                if (text := _history_option_text(row["value"], 40))
            )
        )
        tags = list(
            dict.fromkeys(
                text
                for row in tag_rows[:tag_limit]
                if (text := _history_option_text(row["value"], 120))
            )
        )
        return NotificationHistoryFilterOptions(
            machines=machines,
            agents=agents,
            tags=tags,
            truncated=(
                len(machine_rows) > machine_limit
                or len(agent_rows) > agent_limit
                or len(tag_rows) > tag_limit
            ),
        )

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
        """PostToolUse 到达时,按基础键与 turn_id resolve 唯一匹配的活跃 permission。

        双方都有 turn_id 时必须相等；同一 turn 命中多条视为歧义并保持 no-op。为兼容
        旧 Bridge/历史通知，仅在没有带其它 turn_id 的候选且恰好只有一条 legacy 候选
        时回退。incoming 缺少 turn_id 时也只接受唯一基础键候选。宁可交给会话结束或
        TTL 兜底，也不错误清除仍在等待用户的审批。
        """
        incoming_key = _hook_resolution_key(source=source, session_id=session_id, metadata=metadata)
        incoming_turn_id = _hook_turn_id(metadata)
        now = utc_now()
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT * FROM notifications WHERE status = ? ORDER BY created_at DESC",
                (NotificationStatus.active.value,),
            ).fetchall()
            candidates: list[tuple[NotificationPublic, str]] = []
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
                candidates.append((notification, _hook_turn_id(meta)))

            matched: NotificationPublic | None = None
            if incoming_turn_id:
                exact = [
                    notification
                    for notification, stored_turn_id in candidates
                    if stored_turn_id == incoming_turn_id
                ]
                if len(exact) == 1:
                    matched = exact[0]
                elif not exact and all(not stored_turn_id for _, stored_turn_id in candidates):
                    legacy = [notification for notification, _ in candidates]
                    if len(legacy) == 1:
                        matched = legacy[0]
            elif len(candidates) == 1:
                matched = candidates[0][0]

            if matched is None:
                return None

            self._conn.execute(
                """
                INSERT OR IGNORE INTO acks(notification_id, device_id, ack_at, reason)
                VALUES (?, ?, ?, ?)
                """,
                (matched.id, device_id, _dt(now), reason),
            )
            self._conn.execute(
                """
                UPDATE notifications
                SET status = ?, updated_at = ?
                WHERE id = ?
                """,
                (NotificationStatus.acknowledged.value, _dt(now), matched.id),
            )
            return self._append_event(
                SyncEvent(
                    event_id=new_id(),
                    event_type=EventType.notification_acknowledged,
                    created_at=now,
                    notification_id=matched.id,
                    ack_by_device_id=device_id,
                    ack_at=now,
                    reason=reason,
                )
            )

    def acknowledge_pending_permissions_for_session(
        self,
        *,
        source: str,
        session_id: str | None,
        device_id: str,
        reason: str,
        exclude_notification_id: str | None = None,
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
                if notification.id == exclude_notification_id:
                    continue
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

    def acknowledge_legacy_noise_notifications(self, reason: str = "migration_cleanup") -> list[SyncEvent]:
        """一次性迁移:把 active 的噪声类 hook 通知(PostToolUse/idle/paused/无内容 completed)
        置为 acknowledged,清空"服务端创建层过滤"上线前堆积的历史(实测 PostToolUse 占 active
        的 95%)。幂等——只动 status=active。排除 needs-confirmation(保留未处理权限请求);判定
        委托 hook_policy.is_noise_hook_event,与创建过滤同策略,故 failure/有内容的通知保留。
        不写 acks 表(外键约束,迁移无真实设备),仅 UPDATE status + 追加
        notification.acknowledged 事件(ack_by_device_id=None),返回供启动广播。
        """
        now = utc_now()
        events: list[SyncEvent] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT id, source, title, metadata FROM notifications WHERE status = ?",
                (NotificationStatus.active.value,),
            ).fetchall()
            for row in rows:
                title_lower = (row["title"] or "").lower()
                if "needs confirmation" in title_lower:
                    continue
                try:
                    metadata = json.loads(row["metadata"]) if row["metadata"] else {}
                except (TypeError, ValueError):
                    metadata = {}
                event_name = str(
                    metadata.get("hook_event_name") or metadata.get("hook_event_type") or ""
                ).lower()
                if not event_name:
                    continue
                raw = metadata.get("raw")
                if not is_noise_hook_event(
                    source=str(row["source"] or "").lower(),
                    event_name=event_name,
                    notification_type=str(metadata.get("notification_type") or "").lower(),
                    hook_status=str(metadata.get("hook_status") or "").lower(),
                    title=title_lower,
                    body_generated=str(metadata.get("body_generated") or "").lower() == "true",
                    cwd=str(metadata.get("cwd") or ""),
                    transcript_path=str(metadata.get("transcript_path") or metadata.get("transcriptPath") or ""),
                    permission_mode=str(metadata.get("permission_mode") or metadata.get("permissionMode") or ""),
                    raw=raw if isinstance(raw, dict) else None,
                ):
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

    def _insert_notification(
        self,
        notification: NotificationPublic,
        *,
        dedupe_key: str | None = None,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO notifications (
                id, dedupe_key, source, session_id, origin_device_id, origin_device_name,
                origin_device_platform, title, body, level, status,
                created_at, updated_at, expires_at, requires_ack, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                notification.id,
                dedupe_key,
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
            notification_pause_until=_parse_dt(row["notification_pause_until"]),
            session_state=DeviceSessionState(row["session_state"] or DeviceSessionState.unknown.value),
            session_state_updated_at=_parse_dt(row["session_state_updated_at"]),
        )
