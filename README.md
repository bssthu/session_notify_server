# session_notify_server

把 Codex、Claude Code 等开发工具的会话状态同步到多台设备。

## 本地运行

仅本机调试（HTTP，**不支持**多设备扫码绑定——移动端证书 pinning 只走 TLS）：

```powershell
uv sync
uv run uvicorn app.main:app --reload --port 8765 --log-config logging.json
```

HTTPS/WSS 开发运行（**多设备扫码绑定必须用此方式**）：

```powershell
.\scripts\generate_self_signed_cert.ps1   # 首次运行需要,生成自签证书到 runtime/secrets/
.\scripts\run_dev_server.ps1 -HostAddress 0.0.0.0   # 监听所有网卡;默认 127.0.0.1 只回环,移动端/局域网设备连不上
```

> 多设备绑定(桌面端「绑定新设备」生成二维码、移动端扫码)要求服务端以 HTTPS 启动:二维码里的服务端地址取自服务端实际协议,HTTP 启动会编出 `http://` 地址,而 Android 强制 HTTPS,会报 `baseUrl must use HTTPS`。HTTPS 下,Windows 桌面端首次连接会自动固定证书指纹(TOFU)、二维码也会带上服务端自报的指纹,移动端一扫即绑,无需手动配置指纹。**移动端要连上,服务端必须 `-HostAddress 0.0.0.0` 监听所有网卡**(默认 127.0.0.1 只回环,局域网设备连不上),并在 Windows 防火墙放行 8765 入站。

## 测试

```powershell
uv run pytest
```

## 首版能力

- 设备绑定和 bearer token 认证。
- refresh token 换取/轮换 access token。
- 通知创建、拉取、确认和过期。
- WebSocket 推送 `notification.created` / `notification.acknowledged`，支持 query token 和 `Authorization` header。
- 幂等 ack：任一设备确认后，通知状态以服务端为准。
- Codex / Claude Code hook payload 到统一通知的基础映射。
- SQLite + WAL 本地存储。
- 自签名证书生成脚本和 Docker Compose 部署骨架。
- HTTPS/WSS 启动脚本，Compose 默认使用 `runtime/secrets/server.crt` 和 `server.key`。
- `protocol/openapi.yaml` 和 `protocol/ws-events.schema.json` 作为客户端协议源头。
