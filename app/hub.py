from __future__ import annotations

import asyncio
from collections.abc import Callable

from fastapi import WebSocket, WebSocketDisconnect

from .schemas import SyncEvent


class WebSocketHub:
    def __init__(self) -> None:
        self._connections: dict[WebSocket, tuple[str, Callable[[], bool]]] = {}
        self._lock = asyncio.Lock()

    async def connect(
        self, websocket: WebSocket, device_id: str,
        authorized: Callable[[], bool],
    ) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[websocket] = (device_id, authorized)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.pop(websocket, None)

    async def broadcast(
        self,
        event: SyncEvent,
        should_deliver: Callable[[SyncEvent, str], bool] | None = None,
        prepare_event: Callable[[SyncEvent, str], SyncEvent] | None = None,
    ) -> None:
        shared_payload = None if prepare_event is not None else event.model_dump(mode="json")
        async with self._lock:
            connections = list(self._connections.items())
        stale: list[WebSocket] = []
        for websocket, (device_id, authorized) in connections:
            if not authorized():
                stale.append(websocket)
                continue
            if should_deliver is not None and not should_deliver(event, device_id):
                continue
            payload = (
                prepare_event(event, device_id).model_dump(mode="json")
                if prepare_event is not None
                else shared_payload
            )
            try:
                await asyncio.wait_for(websocket.send_json(payload), timeout=5.0)
            except (WebSocketDisconnect, RuntimeError, OSError, asyncio.TimeoutError):
                stale.append(websocket)
        if stale:
            async with self._lock:
                for websocket in stale:
                    self._connections.pop(websocket, None)
            for websocket in stale:
                try:
                    await asyncio.wait_for(websocket.close(code=1008), timeout=1.0)
                except (WebSocketDisconnect, RuntimeError, OSError, asyncio.TimeoutError):
                    pass
