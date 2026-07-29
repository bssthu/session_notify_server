from __future__ import annotations

import logging

from app.logging_setup import UvicornProtocolHintFilter
from uvicorn.logging import AccessFormatter


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


def test_uvicorn_filter_redacts_websocket_query_tokens():
    record = logging.LogRecord(
        "uvicorn.error",
        logging.INFO,
        __file__,
        1,
        '%s - "WebSocket %s" [accepted]',
        ("203.0.113.10:1234", "/api/v1/ws?token=secret-token&client=windows"),
        None,
    )

    assert UvicornProtocolHintFilter().filter(record) is True
    message = record.getMessage()
    assert "secret-token" not in message
    assert "token=[REDACTED]" in message
    assert "client=windows" in message


def test_uvicorn_filter_redacts_access_tokens_case_insensitively():
    record = _record(
        "uvicorn.access",
        'GET /api/v1/ws?Access_Token=another-secret HTTP/1.1',
    )

    assert UvicornProtocolHintFilter().filter(record) is True
    assert "another-secret" not in record.getMessage()
    assert "Access_Token=[REDACTED]" in record.getMessage()


def test_uvicorn_access_formatter_keeps_working_after_token_redaction():
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        (
            "203.0.113.10:1234",
            "GET",
            "/api/v1/ws?token=formatter-secret",
            "1.1",
            200,
        ),
        None,
    )
    formatter = AccessFormatter(
        '%(client_addr)s - "%(request_line)s" %(status_code)s'
    )

    assert UvicornProtocolHintFilter().filter(record) is True
    formatted = formatter.format(record)
    assert "formatter-secret" not in formatted
    assert "token=[REDACTED]" in formatted
