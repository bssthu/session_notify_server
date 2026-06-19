from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from .hub import WebSocketHub
from .logging_setup import configure_server_logging
from .schemas import (
    AckRequest,
    AckResponse,
    AccessTokenResponse,
    DeviceBindRequest,
    DeviceBindResponse,
    DevicePublic,
    EventsResponse,
    HookPayload,
    NotificationCreate,
    NotificationLevel,
    NotificationPublic,
    NotificationStatus,
    TokenRefreshRequest,
    utc_now,
)
from .storage import Storage

configure_server_logging()

# hook 来源的通知默认 24h 后过期(可由 SESSION_NOTIFY_HOOK_TTL_HOURS 覆盖):permission
# request 等若无对应 PostToolUse resolve(用户拒绝 / Notification 超时提醒 / 历史堆积),
# 靠 TTL 兜底,避免永远 active、被客户端重启 reload 重显。
HOOK_NOTIFICATION_TTL = timedelta(hours=int(os.getenv("SESSION_NOTIFY_HOOK_TTL_HOURS", "24")))
_EXPIRE_POLL_INTERVAL_SECONDS = int(os.getenv("SESSION_NOTIFY_EXPIRE_POLL_SECONDS", "60"))


def _resolve_hook_body(payload: HookPayload) -> tuple[str, bool]:
    command = payload.command
    if command is None and payload.tool_input:
        raw_command = payload.tool_input.get("command")
        command = raw_command if isinstance(raw_command, str) else None

    body = (
        payload.message
        or payload.title
        or payload.prompt
        or command
        or payload.summary
        or payload.last_assistant_message
    )
    return (body, False) if body else ("Session event received.", True)


def _hook_metadata(payload: HookPayload, body_generated: bool) -> dict[str, object]:
    extra = payload.model_extra or {}
    metadata: dict[str, object] = {
        "hook_event_type": payload.event_type,
        "hook_event_name": payload.hook_event_name,
        "hook_status": payload.hook_status,
        "notification_type": payload.notification_type,
        "cwd": payload.cwd,
        "transcript_path": payload.transcript_path,
        "tool_name": payload.tool_name,
        **extra,
        **payload.metadata,
    }
    if payload.tool_input is not None:
        metadata["tool_input"] = payload.tool_input
    metadata["body_generated"] = body_generated
    return {key: value for key, value in metadata.items() if value is not None}


def _resolve_hook_notification(source: str, payload: HookPayload) -> tuple[NotificationLevel, str]:
    event_type = (payload.event_type or payload.hook_event_name or "").lower()
    notification_type = (payload.notification_type or "").lower()
    hook_status = (payload.hook_status or "").lower()
    text = " ".join((event_type, notification_type, hook_status))

    if any(key in text for key in ("auth", "approval", "permission", "confirm", "input", "elicitation")):
        return NotificationLevel.critical, f"{source} needs confirmation"
    if any(key in text for key in ("failure", "failed", "error", "stopfailure")):
        return NotificationLevel.important, f"{source} needs attention"
    if any(key in text for key in ("done", "complete", "success", "finish", "stop", "taskcompleted")):
        return NotificationLevel.success, f"{source} completed"
    if "idle" in text:
        return NotificationLevel.important, f"{source} idle"
    return NotificationLevel.info, f"{source} update"


def create_app(db_path: str | Path | None = None) -> FastAPI:
    storage = Storage(db_path or os.getenv("SESSION_NOTIFY_DB", "runtime/session_notify.db"))
    hub = WebSocketHub()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        # 一次性回填历史 hook 通知的 TTL(幂等),并立即过期一轮 + 广播,
        # 清理 TTL 上线前堆积的 active hook 通知(重启即生效)。
        storage.backfill_hook_expiry(HOOK_NOTIFICATION_TTL)
        for event in storage.expire_due_notifications():
            await hub.broadcast(event)
        expire_task = asyncio.create_task(_expire_due_loop(storage, hub))
        try:
            yield
        finally:
            expire_task.cancel()
            try:
                await expire_task
            except asyncio.CancelledError:
                pass
            except Exception:  # pragma: no cover
                pass
            storage.close()

    app = FastAPI(title="Session Notify", version="0.1.0", lifespan=lifespan)
    app.state.storage = storage
    app.state.hub = hub

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/devices/bind", response_model=DeviceBindResponse)
    def bind_device(request: DeviceBindRequest) -> DeviceBindResponse:
        return storage.bind_device(request.name, request.platform)

    @app.post("/api/v1/auth/refresh", response_model=AccessTokenResponse)
    def refresh_access_token(request: TokenRefreshRequest) -> AccessTokenResponse:
        response = storage.refresh_access_token(request.refresh_token)
        if response is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        return response

    def current_device(
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> DevicePublic:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        device = storage.authenticate(token)
        if device is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
        return device

    @app.post("/api/v1/notifications", response_model=NotificationPublic)
    async def create_notification(
        request: NotificationCreate,
        device: DevicePublic = Depends(current_device),
    ) -> NotificationPublic:
        notification, event = storage.create_notification(request)
        await hub.broadcast(event)
        return notification

    @app.post("/api/v1/hooks/{source}", response_model=NotificationPublic)
    async def receive_hook(
        source: str,
        payload: HookPayload,
        device: DevicePublic = Depends(current_device),
    ) -> NotificationPublic:
        level, title = _resolve_hook_notification(source, payload)
        body, body_generated = _resolve_hook_body(payload)
        hook_meta = _hook_metadata(payload, body_generated)
        request = NotificationCreate(
            source=source,
            session_id=payload.session_id or "local",
            title=title,
            body=body,
            level=level,
            expires_at=utc_now() + HOOK_NOTIFICATION_TTL,
            metadata=hook_meta,
        )
        notification, event = storage.create_notification(request)
        await hub.broadcast(event)
        # 工具执行完成(PostToolUse)意味着对应的权限请求已被批准:按配对键自动 resolve
        # 匹配的活跃 permission request,避免它永远 active、被客户端重启时 reload 重显。
        if (payload.hook_event_name or "").lower() == "posttooluse":
            resolved = storage.resolve_pending_permission(
                source=source,
                session_id=payload.session_id or "local",
                metadata=hook_meta,
                device_id=device.id,
                reason="auto_resolved",
            )
            if resolved is not None:
                await hub.broadcast(resolved)
        return notification

    @app.get("/api/v1/notifications", response_model=list[NotificationPublic])
    def list_notifications(
        status_filter: list[NotificationStatus] | None = Query(default=None, alias="status"),
        device: DevicePublic = Depends(current_device),
    ) -> list[NotificationPublic]:
        return storage.list_notifications(status_filter or [NotificationStatus.active])

    @app.post("/api/v1/notifications/{notification_id}/ack", response_model=AckResponse)
    async def acknowledge_notification(
        notification_id: str,
        request: AckRequest,
        device: DevicePublic = Depends(current_device),
    ) -> AckResponse:
        try:
            response, event = storage.acknowledge(notification_id, device.id, request.reason)
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found") from None
        if event is not None:
            await hub.broadcast(event)
        return response

    @app.get("/api/v1/events", response_model=EventsResponse)
    def list_events(
        since_event_id: str | None = None,
        device: DevicePublic = Depends(current_device),
    ) -> EventsResponse:
        return EventsResponse(events=storage.events_after(since_event_id))

    @app.websocket("/api/v1/ws")
    async def websocket_endpoint(websocket: WebSocket, token: str | None = None) -> None:
        auth_header = websocket.headers.get("authorization")
        header_token = None
        if auth_header and auth_header.lower().startswith("bearer "):
            header_token = auth_header.split(" ", 1)[1].strip()
        device = storage.authenticate(header_token or token or "")
        await hub.connect(websocket)
        if device is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            await hub.disconnect(websocket)
            return
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            await hub.disconnect(websocket)

    return app


async def _expire_due_loop(storage: Storage, hub: WebSocketHub) -> None:
    """定期过期到期通知并广播 expire 事件,让实时连接的客户端及时移除。
    后台任务:瞬时错误不应终止循环。
    """
    while True:
        await asyncio.sleep(_EXPIRE_POLL_INTERVAL_SECONDS)
        try:
            for event in storage.expire_due_notifications():
                await hub.broadcast(event)
        except Exception:  # pragma: no cover
            pass


app = create_app()
