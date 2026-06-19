from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from .hub import WebSocketHub
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
)
from .storage import Storage


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
        try:
            yield
        finally:
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
        request = NotificationCreate(
            source=source,
            session_id=payload.session_id or "local",
            title=title,
            body=body,
            level=level,
            metadata=_hook_metadata(payload, body_generated),
        )
        notification, event = storage.create_notification(request)
        await hub.broadcast(event)
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


app = create_app()
