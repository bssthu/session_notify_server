from __future__ import annotations

import json
import logging.config
import sys
from pathlib import Path

_CONFIGURED = False
_INVALID_HTTP_REQUEST = "Invalid HTTP request received."
_PROTOCOL_MISMATCH_HINT = (
    "Invalid HTTP request received. Tip: this often means an HTTPS client is "
    "talking to this plain HTTP port. If the client reports EPROTO or "
    "WRONG_VERSION_NUMBER, either change the client ServerBaseUri to "
    "http://<host>:<port>, or start the server with TLS via "
    "scripts/run_dev_server.ps1 or scripts/run_dev_server.sh."
)


class UvicornProtocolHintFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name.startswith("uvicorn") and record.getMessage() == _INVALID_HTTP_REQUEST:
            record.msg = _PROTOCOL_MISMATCH_HINT
            record.args = ()
        return True


def _cli_supplies_log_config(argv: list[str]) -> bool:
    return "--log-config" in argv or any(arg.startswith("--log-config=") for arg in argv)


def configure_server_logging(config_path: str | Path | None = None) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    if config_path is None and _cli_supplies_log_config(sys.argv):
        _install_protocol_hint_filter()
        _CONFIGURED = True
        return

    path = Path(config_path) if config_path is not None else Path(__file__).resolve().parent.parent / "logging.json"
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            logging.config.dictConfig(json.load(handle))
    _install_protocol_hint_filter()
    _CONFIGURED = True


def _install_protocol_hint_filter() -> None:
    for logger_name in ("uvicorn", "uvicorn.error", ""):
        logger = logging.getLogger(logger_name)
        for handler in logger.handlers:
            if not any(isinstance(item, UvicornProtocolHintFilter) for item in handler.filters):
                handler.addFilter(UvicornProtocolHintFilter())
