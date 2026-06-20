"""读取服务端 TLS 证书并计算指纹。

「绑定新设备」二维码需要编入证书指纹(走 cert pinning),而指纹的权威来源是
服务端自己的证书。这里读证书文件算出 SHA-256(整个 DER 证书,与客户端
X509Certificate.getEncoded()/Node cert.raw 口径一致),随 pair/issue 返回,
免去客户端预先手填指纹——符合设计稿的 TOFU("连接后固定指纹")思路。
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

from .security import sha256_fingerprint

# 证书文件路径:开发模式相对工作目录,compose 用 SESSION_NOTIFY_CERT_FILE 指向绝对路径。
_DEFAULT_CERT_FILE = "runtime/secrets/server.crt"


def server_certificate_fingerprint() -> str | None:
    """返回服务端证书的 SHA-256 指纹;读不到或解析失败时返回 None(不阻塞配对)。"""
    cert_path = Path(os.getenv("SESSION_NOTIFY_CERT_FILE", _DEFAULT_CERT_FILE))
    try:
        pem = cert_path.read_bytes().decode("ascii", errors="strict")
    except OSError:
        return None
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except ValueError:
        return None
    return sha256_fingerprint(der)
