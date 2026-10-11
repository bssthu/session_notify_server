import importlib.util
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("compose_ports", SOURCE / "deploy/compose_ports.py")
ports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ports)


def config(container=9876, host=19876, host_ip="0.0.0.0"):
    return {"services": {"server": {
        "command": ["uvicorn", "app.main:app", "--port", str(container)],
        "ports": [{"target": container, "published": str(host), "host_ip": host_ip, "protocol": "tcp"}],
    }}}


def test_distinct_container_and_host_ports():
    assert ports.resolve_ports(config()) == (9876, 19876)


def test_ipv6_duplicate_publication_does_not_make_ipv4_ambiguous():
    value = config()
    value["services"]["server"]["ports"].append(
        {"target": 9876, "published": "19876", "host_ip": "::", "protocol": "tcp"})
    assert ports.resolve_ports(value) == (9876, 19876)


@pytest.mark.parametrize("value", [0, -1, 65536, True, "1;false", "19876-19877", "１２３"])
def test_invalid_port_rejected(value):
    with pytest.raises(ValueError):
        ports.resolve_ports(config(host=value))


@pytest.mark.parametrize("host_ip", ["::", "::1", "192.0.2.1"])
def test_ipv4_loopback_inaccessible_mapping_rejected(host_ip):
    with pytest.raises(ValueError, match="loopback-accessible"):
        ports.resolve_ports(config(host_ip=host_ip))


def test_ambiguous_publications_rejected():
    value = config()
    value["services"]["server"]["ports"].append({"target": 9876, "published": "19877"})
    with pytest.raises(ValueError, match="exactly one"):
        ports.resolve_ports(value)


def test_no_matching_publication_rejected():
    value = config()
    value["services"]["server"]["ports"][0]["target"] = 1234
    with pytest.raises(ValueError, match="loopback-accessible"):
        ports.resolve_ports(value)


@pytest.mark.parametrize("command", [[], ["uvicorn", "--port"], "uvicorn --port 9876",
                                     ["uvicorn", "--port", "9876", "--port", "1234"]])
def test_missing_or_ambiguous_listener_rejected(command):
    value = config()
    value["services"]["server"]["command"] = command
    with pytest.raises(ValueError, match="--port"):
        ports.resolve_ports(value)
