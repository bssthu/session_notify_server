from __future__ import annotations

import json
import logging.config
import sys
from pathlib import Path

_CONFIGURED = False


def _cli_supplies_log_config(argv: list[str]) -> bool:
    return "--log-config" in argv or any(arg.startswith("--log-config=") for arg in argv)


def configure_server_logging(config_path: str | Path | None = None) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    if config_path is None and _cli_supplies_log_config(sys.argv):
        _CONFIGURED = True
        return

    path = Path(config_path) if config_path is not None else Path(__file__).resolve().parent.parent / "logging.json"
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            logging.config.dictConfig(json.load(handle))
    _CONFIGURED = True
