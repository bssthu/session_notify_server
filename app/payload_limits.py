"""Limits shared by every HTTP deployment, including direct Uvicorn access."""
from __future__ import annotations

import asyncio
import json
import math

from starlette.responses import JSONResponse

MAX_REQUEST_BYTES = 256 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_VALUES = 4096


class PayloadValidationError(ValueError):
    pass


LOCAL_METADATA_KEYS = frozenset({"localonly", "countdownlocal", "alarmlocal", "controllable", "alarmpreview"})
SCALAR_METADATA_KEYS = frozenset({
    "kind", "tag", "sessionnotifytag", "privacytag", "sessionnotifyprivacytag",
    "hookeventtype", "hookeventname", "hookstatus", "raweventtype", "notificationtype",
    "sourcetool", "toolname", "permissionmode", "permissionmodesource", "bodygenerated",
    "cwd", "workingdirectory", "transcriptpath", "sessionid", "turnid", "generationid", "promptid",
    "deliveryid", "deliveryguarantee", "ingestsource", "eventfamily", "eventcorrelation",
    "remainingfraction", "remainingseconds", "totalseconds", "durationseconds",
    "countdownstatus", "countdownrun", "countdownnodekey", "countdownnodelabel",
    "alarmtime", "alarmlabel", "alarmrepeat", "alarmrepeatlabel", "alarmeffect", "alarmeventkey",
    "alarmsnoozeminutes", "color", "message", "prompt", "command", "summary", "lastassistantmessage",
}) | LOCAL_METADATA_KEYS


def metadata_key(key: str) -> str:
    return key.replace("_", "").lower()


def validate_json_budget(value, *, max_bytes: int = MAX_METADATA_BYTES) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_VALUES:
            raise PayloadValidationError("JSON exceeds the depth or value-count limit")
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise PayloadValidationError("JSON object keys must be strings")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif not isinstance(item, (str, int, float, bool, type(None))):
            raise PayloadValidationError("Metadata must contain JSON values")
        elif isinstance(item, float) and not math.isfinite(item):
            raise PayloadValidationError("Metadata numbers must be finite")
    try:
        size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except UnicodeEncodeError:
        raise PayloadValidationError("Metadata must contain valid Unicode text") from None
    if size > max_bytes:
        raise PayloadValidationError(f"JSON exceeds the {max_bytes}-byte limit")


def without_local_metadata(metadata: dict) -> dict:
    return {key: value for key, value in metadata.items() if metadata_key(key) not in LOCAL_METADATA_KEYS}


def validate_metadata(metadata: dict) -> dict:
    validate_json_budget(metadata)
    for controls in (metadata, metadata.get("raw")):
        if not isinstance(controls, dict):
            continue
        for key, value in controls.items():
            if metadata_key(key) in SCALAR_METADATA_KEYS and isinstance(value, (dict, list)):
                raise PayloadValidationError(f"Metadata field {key} must be a scalar")
    return without_local_metadata(metadata)


class RequestBodyLimitMiddleware:
    """Buffer only a bounded request before FastAPI performs JSON parsing."""
    def __init__(self, app, max_bytes: int = MAX_REQUEST_BYTES, timeout: float = 15):
        self.app, self.max_bytes, self.timeout = app, max_bytes, timeout

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            return await self.app(scope, receive, send)
        lengths = [value for key, value in scope.get("headers", []) if key.lower() == b"content-length"]
        try:
            too_large = any(int(value) > self.max_bytes for value in lengths)
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
        if too_large:
            return await self.reject(scope, receive, send)
        body = bytearray()
        try:
            async with asyncio.timeout(self.timeout):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > self.max_bytes:
                        return await self.reject(scope, receive, send)
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await JSONResponse({"detail": "Request body timed out"}, status_code=408)(scope, receive, send)
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, bounded_receive, send)

    async def reject(self, scope, receive, send):
        await JSONResponse({"detail": {"code": "request_too_large", "message": f"Request body exceeds {self.max_bytes} bytes"}},
                           status_code=413)(scope, receive, send)
