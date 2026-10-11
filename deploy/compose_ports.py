"""Resolve backend TLS ports from Docker Compose's rendered JSON configuration."""

from __future__ import annotations

import json
import sys
from typing import Any


def port_number(value: Any) -> int:
    if isinstance(value, bool) or not str(value).isascii() or not str(value).isdigit():
        raise ValueError("Backend ports must be integers from 1 to 65535")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("Backend ports must be integers from 1 to 65535")
    return port


def resolve_ports(config: dict[str, Any]) -> tuple[int, int]:
    server = config.get("services", {}).get("server", {})
    command = server.get("command", [])
    if not isinstance(command, list) or command.count("--port") != 1:
        raise ValueError("server.command must contain exactly one explicit --port")
    index = command.index("--port") + 1
    if index >= len(command):
        raise ValueError("server.command is missing the --port value")
    container_port = port_number(command[index])
    published = set()
    for mapping in server.get("ports", []):
        if not isinstance(mapping, dict):
            raise ValueError("Expected normalized Compose ports; use config --format json")
        if mapping.get("protocol", "tcp") != "tcp" or port_number(mapping.get("target")) != container_port:
            continue
        # Preflight and the updater connect over IPv4 loopback.
        if mapping.get("host_ip", "0.0.0.0") not in ("", "0.0.0.0", "127.0.0.1"):
            continue
        published.add(port_number(mapping.get("published")))
    if len(published) != 1:
        raise ValueError("Publish the server TLS port on exactly one IPv4 loopback-accessible host port")
    return container_port, published.pop()


def main() -> int:
    try:
        container_port, host_port = resolve_ports(json.load(sys.stdin))
    except (ValueError, TypeError, AttributeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(container_port, host_port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
