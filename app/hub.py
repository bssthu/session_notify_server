from __future__ import annotations

import asyncio
from collections.abc import Callable

from fastapi import WebSocket

from .schemas import SyncEvent


class WebSocketHub:
    def __init__(self) -> None:
        self._connections: dict[WebSocket, str] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, device_id: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[websocket] = device_id

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.pop(websocket, None)

    async def broadcast(
        self,
        event: SyncEvent,
        should_deliver: Callable[[SyncEvent, str], bool] | None = None,
    ) -> None:
        payload = event.model_dump(mode="json")
        async with self._lock:
            connections = list(self._connections.items())
        stale: list[WebSocket] = []
        for websocket, device_id in connections:
            if should_deliver is not None and not should_deliver(event, device_id):
                continue
            try:
                await websocket.send_json(payload)
            except RuntimeError:
                stale.append(websocket)
        if stale:
            async with self._lock:
                for websocket in stale:
                    self._connections.pop(websocket, None)
