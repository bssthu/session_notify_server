from __future__ import annotations

import logging

from app.logging_setup import UvicornProtocolHintFilter


def _record(name: str, message: str) -> logging.LogRecord:
    return logging.LogRecord(name, logging.WARNING, __file__, 1, message, (), None)


def test_uvicorn_invalid_http_request_gets_protocol_hint():
    record = _record("uvicorn.error", "Invalid HTTP request received.")

    assert UvicornProtocolHintFilter().filter(record) is True

    message = record.getMessage()
    assert "Invalid HTTP request received." in message
    assert "HTTPS client" in message
    assert "plain HTTP port" in message
    assert "WRONG_VERSION_NUMBER" in message
    assert "http://<host>:<port>" in message


def test_uvicorn_protocol_hint_filter_leaves_other_logs_unchanged():
    record = _record("uvicorn.error", "Application startup complete.")

    assert UvicornProtocolHintFilter().filter(record) is True
    assert record.getMessage() == "Application startup complete."

    non_uvicorn = _record("app.main", "Invalid HTTP request received.")
    assert UvicornProtocolHintFilter().filter(non_uvicorn) is True
    assert non_uvicorn.getMessage() == "Invalid HTTP request received."
