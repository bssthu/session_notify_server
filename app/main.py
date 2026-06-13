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
        event_type = (payload.event_type or "").lower()
        text = payload.message or payload.prompt or payload.command or payload.summary or "Session event received."
        if any(key in event_type for key in ("auth", "approval", "permission", "confirm", "input")):
            level = NotificationLevel.critical
            title = f"{source} needs confirmation"
        elif any(key in event_type for key in ("done", "complete", "success", "finish")):
            level = NotificationLevel.success
            title = f"{source} completed"
        else:
            level = NotificationLevel.info
            title = f"{source} update"
        request = NotificationCreate(
            source=source,
            session_id=payload.session_id or "local",
            title=title,
            body=text,
            level=level,
            metadata={"hook_event_type": payload.event_type, **payload.metadata},
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
