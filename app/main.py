from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status

from .hub import WebSocketHub
from .logging_setup import configure_server_logging
from .schemas import (
    AckRequest,
    AckResponse,
    AccessTokenResponse,
    DeviceBindRequest,
    DeviceBindResponse,
    DevicePublic,
    DeviceUpdateRequest,
    EventsResponse,
    HookPayload,
    NotificationCreate,
    NotificationLevel,
    NotificationPublic,
    NotificationStatus,
    PairConsumeRequest,
    PairIssueResponse,
    TokenRefreshRequest,
    utc_now,
)
from .storage import Storage

configure_server_logging()

# hook 来源的通知默认 24h 后过期(可由 SESSION_NOTIFY_HOOK_TTL_HOURS 覆盖):permission
# request 等若无对应 PostToolUse resolve(用户拒绝 / Notification 超时提醒 / 历史堆积),
# 靠 TTL 兜底,避免永远 active、被客户端重启 reload 重显。
HOOK_NOTIFICATION_TTL = timedelta(hours=int(os.getenv("SESSION_NOTIFY_HOOK_TTL_HOURS", "24")))
# approval 类(needs confirmation)通知即时性强,用短 TTL:即便无 PostToolUse resolve、也无
# 会话结束清理,也不会长期 active 被客户端重启 reload 重显。其它 hook 通知维持 24h。
HOOK_PERMISSION_TTL = timedelta(minutes=int(os.getenv("SESSION_NOTIFY_PERMISSION_TTL_MINUTES", "30")))
# 会话结束类 hook:到达即代表该会话的旧 permission request 必然已无意义(用户已拒绝/已处理/
# 会话中断且不会有 PostToolUse),触发按会话批量 acknowledge 兜底清理。
_HOOK_EVENTS_THAT_FINALIZE_SESSION = frozenset({"stop", "taskcompleted", "stopfailure", "subagentstop"})
# 设备 token 寿命:access 短期(请求凭证,到期靠客户端自动 refresh)、refresh 长期(仅换新 access,
# 不轮换)。refresh 到期后需重新绑定。默认 access 1h / refresh 90d。
ACCESS_TOKEN_TTL = timedelta(seconds=int(os.getenv("SESSION_NOTIFY_ACCESS_TTL_SECONDS", "3600")))
REFRESH_TOKEN_TTL = timedelta(days=int(os.getenv("SESSION_NOTIFY_REFRESH_TTL_DAYS", "90")))
# 配对码有效期:已绑设备签发,新设备扫码/输码消费。一次性,默认 5 分钟。
PAIR_CODE_TTL = timedelta(seconds=int(os.getenv("SESSION_NOTIFY_PAIR_CODE_TTL_SECONDS", "300")))
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
    storage = Storage(
        db_path or os.getenv("SESSION_NOTIFY_DB", "runtime/session_notify.db"),
        access_ttl=ACCESS_TOKEN_TTL,
        refresh_ttl=REFRESH_TOKEN_TTL,
        pair_code_ttl=PAIR_CODE_TTL,
    )
    hub = WebSocketHub()
    # 配对模式:strict(默认)= 已有已绑设备后新设备必须持配对码,首台裸 bind 放行;
    # easy = 配对码仅便捷入口,bind 永远放行(逃生口)。在 create_app 内读便于测试切换。
    pair_mode = os.getenv("SESSION_NOTIFY_PAIR_MODE", "strict").lower()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        # 一次性回填历史 hook 通知的 TTL(幂等),并立即过期一轮 + 广播,
        # 清理 TTL 上线前堆积的 active hook 通知(重启即生效)。
        storage.backfill_hook_expiry(HOOK_NOTIFICATION_TTL)
        # 一次性清理 resolve 机制(d67e95d, 2026-06-19)上线前的 active permission request 历史
        # 残留(幂等,只动 active):它们永不会被 PostToolUse resolve,会一直 active 到 TTL,期间
        # 客户端重启 reload 会重显。置 acknowledged 后不再重显。
        for event in storage.acknowledge_legacy_permission_requests():
            await hub.broadcast(event, storage.should_deliver_event_to_device)
        for event in storage.expire_due_notifications():
            await hub.broadcast(event, storage.should_deliver_event_to_device)
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
        # strict 模式:已存在已绑设备时,裸 bind 拒绝。但本机可凭旧 refresh_token 重新绑定
        # (rebind,换发新 token),避免本机凭证丢失时死锁。首台(无设备)直接放行。
        # easy 模式:bind 永远放行,配对码仅作免填地址的便捷入口。
        if pair_mode == "strict" and storage.has_any_device():
            if request.refresh_token:
                rebound = storage.rebind_device(request.refresh_token, request.name, request.platform)
                if rebound is not None:
                    return rebound
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Pairing code required; use POST /api/v1/devices/pair/consume or rebind with refresh_token",
            )
        return storage.bind_device(request.name, request.platform)

    @app.post("/api/v1/devices/reset", response_model=dict)
    def reset_all_devices(request: Request) -> dict:
        # 撤销所有设备回到 bootstrap 态。仅限本机调用(自托管用户在服务端主机操作),
        # 避免远程任意重置。用于 strict 模式下本机凭证全丢、又无其他设备签发配对码的死锁。
        client_host = request.client.host if request.client else ""
        if client_host not in ("127.0.0.1", "::1", "localhost"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device reset is only allowed from localhost")
        return {"revoked": storage.revoke_all_devices()}

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

    @app.post("/api/v1/devices/pair/issue", response_model=PairIssueResponse)
    def issue_pair_code(
        device: DevicePublic = Depends(current_device),
    ) -> PairIssueResponse:
        code, expires_at = storage.issue_pair_code(device)
        return PairIssueResponse(code=code, expires_at=expires_at)

    @app.post("/api/v1/devices/pair/consume", response_model=DeviceBindResponse)
    def consume_pair_code(request: PairConsumeRequest) -> DeviceBindResponse:
        response = storage.consume_pair_code(request.code, request.name, request.platform)
        if response is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired, or already-used pairing code",
            )
        return response

    @app.get("/api/v1/devices", response_model=list[DevicePublic])
    def list_devices(
        device: DevicePublic = Depends(current_device),
    ) -> list[DevicePublic]:
        return storage.list_devices()

    @app.patch("/api/v1/devices/{device_id}", response_model=DevicePublic)
    def update_device(
        device_id: str,
        request: DeviceUpdateRequest,
        device: DevicePublic = Depends(current_device),
    ) -> DevicePublic:
        try:
            return storage.update_device(
                device_id,
                name=request.name,
                notifications_enabled=request.notifications_enabled,
            )
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found") from None
        except ValueError as error:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from None

    @app.delete("/api/v1/devices/{device_id}", response_model=DevicePublic)
    def revoke_device(
        device_id: str,
        device: DevicePublic = Depends(current_device),
    ) -> DevicePublic:
        try:
            return storage.revoke_device(device_id)
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found") from None

    @app.post("/api/v1/notifications", response_model=NotificationPublic)
    async def create_notification(
        request: NotificationCreate,
        device: DevicePublic = Depends(current_device),
    ) -> NotificationPublic:
        notification, event = storage.create_notification(request, origin_device=device)
        await hub.broadcast(event, storage.should_deliver_event_to_device)
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
        # approval 类(needs confirmation)即时性强,用短 TTL;其它 hook 通知维持默认 24h。
        permission_ttl = HOOK_PERMISSION_TTL if "needs confirmation" in title else HOOK_NOTIFICATION_TTL
        request = NotificationCreate(
            source=source,
            session_id=payload.session_id or "local",
            title=title,
            body=body,
            level=level,
            expires_at=utc_now() + permission_ttl,
            metadata=hook_meta,
        )
        notification, event = storage.create_notification(request, origin_device=device)
        await hub.broadcast(event, storage.should_deliver_event_to_device)
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
                await hub.broadcast(resolved, storage.should_deliver_event_to_device)
        # 会话结束类 hook = 该 session 的旧 permission request 必然已无意义(用户已拒绝/已处理/
        # 会话中断,不会有 PostToolUse 到达)。按会话批量 acknowledge 兜底清理,覆盖
        # resolve_pending_permission(只处理 PostToolUse)漏掉的拒绝/中断场景,避免短 TTL
        # 窗口内客户端重启 reload 重显。
        if (payload.hook_event_name or "").lower() in _HOOK_EVENTS_THAT_FINALIZE_SESSION:
            for ev in storage.acknowledge_pending_permissions_for_session(
                source=source,
                session_id=payload.session_id or "local",
                device_id=device.id,
                reason="session_finalized",
            ):
                await hub.broadcast(ev, storage.should_deliver_event_to_device)
        return notification

    @app.get("/api/v1/notifications", response_model=list[NotificationPublic])
    def list_notifications(
        status_filter: list[NotificationStatus] | None = Query(default=None, alias="status"),
        device: DevicePublic = Depends(current_device),
    ) -> list[NotificationPublic]:
        if not device.notifications_enabled:
            return []
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
            await hub.broadcast(event, storage.should_deliver_event_to_device)
        return response

    @app.get("/api/v1/events", response_model=EventsResponse)
    def list_events(
        since_event_id: str | None = None,
        device: DevicePublic = Depends(current_device),
    ) -> EventsResponse:
        return EventsResponse(events=storage.events_after(since_event_id, device))

    @app.websocket("/api/v1/ws")
    async def websocket_endpoint(websocket: WebSocket, token: str | None = None) -> None:
        auth_header = websocket.headers.get("authorization")
        header_token = None
        if auth_header and auth_header.lower().startswith("bearer "):
            header_token = auth_header.split(" ", 1)[1].strip()
        device = storage.authenticate(header_token or token or "")
        if device is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await hub.connect(websocket, device.id)
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
                await hub.broadcast(event, storage.should_deliver_event_to_device)
        except Exception:  # pragma: no cover
            pass


app = create_app()
