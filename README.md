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

Windows 桌面端首次 HTTPS 连接可自动固定证书指纹（TOFU），也可以预先填写证书脚本输出的 SHA-256 指纹。首台设备仍需按下节使用初始化配对码；绑定成功后，桌面端才能通过「绑定新设备」生成二维码。Android 扫码会填入地址、指纹和配对码，再点「连接 / 绑定」完成配对。

二维码中的协议取自服务端请求，Android 只接受 HTTPS。手机应选用可达的局域网地址；`127.0.0.1` 仅供服务端本机使用，`10.0.2.2` 仅供 Android Emulator 访问宿主机。局域网设备连接时，服务端需监听 `0.0.0.0` 或对应网卡，并在防火墙放行 8765 入站。

## 首次绑定与凭据管理

首次绑定（以及重置后的重新绑定）需要在服务端本机生成一次性配对码：

```powershell
uv run python scripts/issue_bootstrap_code.py
# 使用非默认数据库时增加 --db <数据库路径>
# Docker Compose: docker compose exec server python scripts/issue_bootstrap_code.py
```

命令须在服务端项目目录执行，并使用运行中服务的同一个数据库。初始化配对码仅在没有有效设备时可签发，重新签发会废止前一个初始化码；已有有效设备时，应由该设备签发后续配对码。

在客户端填写服务器地址、证书指纹和该配对码即可绑定。配对码默认五分钟有效、只能使用一次；客户端通过 `POST /api/v1/devices/pair/consume` 消费。默认 `strict` 模式下，`POST /api/v1/devices/bind` 只允许携带有效 refresh token 重新绑定已有设备，新设备（包括首台）不允许匿名绑定。`SESSION_NOTIFY_PAIR_MODE` 未知取值拒绝启动；`easy` 仅供隔离开发环境使用，会关闭配对门禁。

凭据全部丢失时，在服务端运行 `uv run python scripts/reset_devices.py`，然后重新生成初始化配对码。HTTP 重置入口已移除；本地重置会同时废止所有未使用配对码。撤销单台设备也会废止该设备签发的码。WebSocket 在令牌过期、轮换或设备撤销后断开，客户端刷新后重连；广播前也会重新检查授权。

隐私隐藏仍是下发过滤，数据库和 Hook 队列不是端到端加密存储。

## Docker Compose

在服务端项目目录执行；证书已存在时跳过生成步骤：

```powershell
.\scripts\generate_self_signed_cert.ps1
docker compose up -d --build
docker compose exec server python scripts/issue_bootstrap_code.py
```

Compose 使用 HTTPS 监听 8765，挂载 `runtime/secrets/` 中的证书和私钥，数据库保存在 `session_notify_data` 命名卷中。初始化和重置命令应通过 `docker compose exec server` 在容器内执行，使用 `/data/session_notify.db`；宿主机默认的 `runtime/session_notify.db` 是另一个数据库。构建通过 `uv sync --frozen --no-dev` 使用 `uv.lock` 中的应用依赖版本。

## 配置

服务从进程环境读取配置；`.env.example` 不会被启动脚本自动加载。PowerShell 中使用 `$env:变量名 = "值"`，Compose 部署则在 `compose.yaml` 的 `environment` 中配置。

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SESSION_NOTIFY_DB` | `runtime/session_notify.db` | SQLite 数据库路径；Compose 覆盖为 `/data/session_notify.db` |
| `SESSION_NOTIFY_PAIR_MODE` | `strict` | 新设备配对门禁 |
| `SESSION_NOTIFY_CERT_FILE` | `runtime/secrets/server.crt` | 配对二维码所需的服务端证书指纹来源 |
| `SESSION_NOTIFY_ACCESS_TTL_SECONDS` | `3600` | access token 有效秒数 |
| `SESSION_NOTIFY_REFRESH_TTL_DAYS` | `90` | refresh token 有效天数 |
| `SESSION_NOTIFY_PAIR_CODE_TTL_SECONDS` | `300` | 已绑定设备签发的配对码有效秒数；本地初始化脚本使用默认五分钟 |
| `SESSION_NOTIFY_HOOK_TTL_HOURS` | `24` | 普通 Hook 通知有效小时数 |
| `SESSION_NOTIFY_PERMISSION_TTL_MINUTES` | `30` | 普通工具权限审批通知有效分钟数 |
| `SESSION_NOTIFY_DEVICE_PRESENCE_TTL_SECONDS` | `90` | Windows 在线状态有效秒数 |

监听地址和端口由 `run_dev_server.ps1 -HostAddress ... -Port ...` 或 uvicorn 参数决定，`.env.example` 的 `SESSION_NOTIFY_HOST` / `SESSION_NOTIFY_PORT` 不会替代这些参数。若通过 `-CertFile` 指定其他证书，还需把 `SESSION_NOTIFY_CERT_FILE` 指向同一文件，保证二维码指纹一致。

## 手动发送测试通知

先从已绑定客户端取得一个新的配对码，再在服务端项目目录运行：

```powershell
uv run python scripts/send_test_notification.py --base-url https://127.0.0.1:8765 --pair-code "PASTE-PAIR-CODE" --all
uv run python scripts/send_test_notification.py --base-url https://127.0.0.1:8765 --stack 3
```

脚本将测试设备的 access token 按地址缓存到 `runtime/.test_device.json`。缓存过期或设备被撤销后，需重新提供 `--pair-code`，不会自动匿名绑定或刷新 token。服务端尚无设备时，可先用本地初始化命令取码。自签证书的校验豁免仅限回环地址；远程地址必须使用 HTTPS 和受信任证书。`--clear` 会确认该设备可见的全部 active 通知，不限于测试通知。

## 测试

```powershell
uv run pytest
```

## 当前能力

- 设备绑定和 bearer token 认证。
- refresh token 换取/轮换 access token。
- 通知创建、拉取、确认和过期；历史查询支持可见性/状态过滤、总数统计与游标分页，查询范围在服务端硬限制为最近 30 天。
- WebSocket 推送 `notification.created` / `notification.acknowledged`，支持 query token 和 `Authorization` header。
- 汇总 Windows 锁屏与通知暂停状态；Android 可按“未锁屏且未暂停”的电脑可用性决定是否展示提醒。
- 幂等 ack：任一设备确认后，通知状态以服务端为准。
- Codex / Claude Code / Cursor / DeepSeek Harness hook payload 到统一通知的基础映射。
- `SESSION_NOTIFY_TAG` 作为 `metadata.tag` 随通知保存，供客户端展示和历史筛选。
- `SESSION_NOTIFY_PRIVACY_TAG`：`hide` 时所有设备下发的正文替换为 `***`；`local` 时仅来源设备看到明文。正文不可见时，metadata 仅保留展示与关联控制字段，移除原始 payload、工具输入和自由文本诊断。服务端存储保持明文；不可见的正文不会进入历史关键词搜索。需要 Windows Hook bundle 11。
- Codex 异步提问按来源设备、会话和完整题目指纹匹配回答，支持跨回合、逐题回答、重复投递和乱序补发；全部回答后持久确认并广播 `notification.acknowledged`。同题歧义时保留；迟到题目使原匹配产生歧义时，撤销未过期通知的自动确认，并通过原 ID 的 `notification.created` 更新两端，手动确认始终保留。Stop 和启动清理不消除未回答的异步问题。需要 Windows Hook bundle 9；应先更新服务端，再更新 Hook。
- SQLite + WAL 本地存储。
- 自签名证书生成脚本和 Docker Compose 部署骨架。
- HTTPS/WSS 启动脚本，Compose 默认使用 `runtime/secrets/server.crt` 和 `server.key`。
- `protocol/openapi.yaml` 和 `protocol/ws-events.schema.json` 作为客户端协议源头。
