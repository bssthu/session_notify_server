# session_notify_server

把 Codex、Claude Code 等开发工具的会话状态同步到多台设备。

## 本地运行

```powershell
uv sync
uv run uvicorn app.main:app --reload --port 8765
```

HTTPS/WSS 开发运行：

```powershell
.\scripts\generate_self_signed_cert.ps1
.\scripts\run_dev_server.ps1
```

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
