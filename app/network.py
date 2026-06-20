"""枚举本机网卡 IPv4 地址。

「绑定新设备」二维码需要写入真实可达的服务端地址(而非 localhost 回环),
这里用 Python 标准库枚举本机非回环 IPv4,交给签发端拼成候选 base URL。
不引入第三方依赖。
"""

from __future__ import annotations

import socket

# UDP "连接"探针地址:仅用于让内核选定出站网卡,不会实际发送数据包。
_PROBE_DESTINATION = ("8.8.8.8", 80)
_LOOPBACK_PREFIX = "127."
_LINK_LOCAL_PREFIX = "169.254."


def _is_usable(ip: str) -> bool:
    return bool(ip) and not ip.startswith(_LOOPBACK_PREFIX) and not ip.startswith(_LINK_LOCAL_PREFIX)


def list_local_ipv4_addresses() -> list[str]:
    """返回本机非回环 IPv4 地址,按"出站主地址优先"排序、去重。

    主路径用 UDP 探针拿出站网卡 IP(跨平台最可靠的单一兜底),
    再用 getaddrinfo(hostname) 补充其余网卡地址。任一步异常都不致命。
    """
    addresses: list[str] = []

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(_PROBE_DESTINATION)
            primary = probe.getsockname()[0]
        finally:
            probe.close()
        if _is_usable(primary):
            addresses.append(primary)
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if _is_usable(ip) and ip not in addresses:
                addresses.append(ip)
    except OSError:
        pass

    return addresses
