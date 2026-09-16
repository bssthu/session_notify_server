# session_notify_server

把 Codex、Claude Code、Cursor 等开发工具的会话状态同步到多台设备。

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
- 通知创建、拉取、确认和过期；历史查询支持可见性/状态过滤、总数统计与游标分页，查询范围在服务端硬限制为最近 30 天。
- WebSocket 推送 `notification.created` / `notification.acknowledged`，支持 query token 和 `Authorization` header。
- 汇总 Windows 锁屏与通知暂停状态；Android 可按“未锁屏且未暂停”的电脑可用性决定是否展示提醒。
- 幂等 ack：任一设备确认后，通知状态以服务端为准。
- Codex / Claude Code / Cursor / DeepSeek Harness hook payload 到统一通知的基础映射。
- `SESSION_NOTIFY_TAG` 作为 `metadata.tag` 随通知保存，供客户端展示和历史筛选。
- `SESSION_NOTIFY_PRIVACY_TAG`：`hide` 时所有设备下发的正文替换为 `***`；`local` 时仅来源设备看到明文。服务端存储保持明文，只在 REST / WebSocket 下发时按查看设备替换；对当前设备不可见的明文正文也不会进入历史关键词搜索。需要 Windows Hook bundle 11。
- Codex 异步提问按来源设备、会话和完整题目指纹匹配回答，支持跨回合、逐题回答、重复投递和乱序补发；全部回答后持久确认并广播 `notification.acknowledged`。同题歧义时保留，Stop 和启动清理不消除未回答的异步问题。需要 Windows Hook bundle 9；应先更新服务端，再更新 Hook。
- SQLite + WAL 本地存储。
- 自签名证书生成脚本和 Docker Compose 部署骨架。
- HTTPS/WSS 启动脚本，Compose 默认使用 `runtime/secrets/server.crt` 和 `server.key`。
- `protocol/openapi.yaml` 和 `protocol/ws-events.schema.json` 作为客户端协议源头。
