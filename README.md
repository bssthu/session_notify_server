# Session Notify 服务端

基于 FastAPI 与 SQLite，将 Codex、Claude Code、Cursor、DeepSeek Harness 等工具的通知同步到多台设备。服务端是协议定义、设备权限、通知状态及事件关联的源头；客户端文档见 [Windows](../session_notify_windows/README.md) 和 [Android](../session_notify_android/README.md)。

本文按 2026-10-09 的仓库实现核对。需要 Python 3.11 或以上版本和 uv；应用依赖版本由 `uv.lock` 锁定。

## 升级兼容性

Codex 异步提问回答兼容旧版引用文本和 Hook bundle 15 的新版结构化格式。新版 `answered_batch` 使用调用 ID、题目序号及完整题目指纹关联，支持选项、自由输入、逐题和批量回答；一组题目全部回答后才同步确认通知。回答正文不上传，断网补发和服务端重启保留关联状态。部署时先更新服务端，再更新 Windows 客户端并执行 Hook「安装 / 更新」；旧版客户端和旧数据库继续兼容。

## 本地运行

以下命令在服务端仓库根目录执行。仅本机调试可使用 HTTP；Android 要求 HTTPS，不能用此地址直接连接：

```powershell
uv sync
uv run uvicorn app.main:app --reload --port 8765 --log-config logging.json
```

多设备连接使用 HTTPS / WSS。首次生成证书前需保证 OpenSSL 可用；已有证书时跳过生成步骤：

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

命令须在服务端项目目录执行，并使用运行中服务的同一个数据库。初始化配对码仅在没有有效设备时可签发，重新签发会废止前一个初始化码；已有有效设备时，应由管理员设备签发后续配对码。

在客户端填写服务器地址、证书指纹和该配对码即可绑定。配对码默认五分钟有效、只能使用一次；客户端通过 `POST /api/v1/devices/pair/consume` 消费。默认 `strict` 模式下，`POST /api/v1/devices/bind` 只允许携带有效刷新令牌重新绑定已有设备，新设备（包括首台）不允许匿名绑定。`SESSION_NOTIFY_PAIR_MODE` 未知取值拒绝启动；`easy` 仅供隔离开发环境使用，会关闭配对门禁。

凭据全部丢失时，在服务端运行 `uv run python scripts/reset_devices.py`，然后重新生成初始化配对码。HTTP 重置入口已移除；本地重置会同时废止所有未使用配对码。撤销或降级管理员设备也会废止该设备签发的码。WebSocket 在令牌过期、轮换或设备撤销后断开，客户端刷新后重连；广播前也会重新检查授权。

### 设备权限

设备角色为 `admin`（管理员）、`member`（普通设备）和 `guest`（游客），由服务端保存和校验，与 Windows / Android 平台无关。

| 操作 | 管理员 | 普通设备 | 游客 |
| --- | --- | --- | --- |
| 发布通知、发送 Hook | 允许 | 允许 | 允许，来源固定为认证设备 |
| 查看设备及在线状态 | 全部 | 全部 | 仅本机，统计也只包含本机 |
| 接收、搜索、确认通知 | 全部 | 全部 | 仅本机发布的通知 |
| 修改本机名称、通知接收设置 | 允许 | 允许 | 允许 |
| 邀请设备、修改其他设备、调整角色（含自己） | 允许 | 禁止（HTTP 403） | 禁止（HTTP 403） |
| 撤销绑定 | 任意设备 | 仅本机 | 仅本机 |

“本机通知”按服务端 `origin_device_id` 判断，不信任请求里的设备字段、元数据或会话名称。游客发布的通知仍按原同步及隐私规则提供给管理员和普通设备；无来源的历史通知不提供给游客。游客确认其他设备通知时返回 404，与不存在的通知一致，不产生副作用。

限制覆盖活跃列表、历史分页及总数、搜索和筛选建议、WebSocket、两种事件补拉接口、设备状态统计，以及 Hook 去重和自动确认。其他设备确认游客的本机通知时，游客只收到状态变化，不收到确认设备 ID 或自定义确认原因。投递 ID 按来源设备隔离，同设备重试仍幂等。

首台设备（包括本机初始化码绑定、`easy` 模式的首台绑定）自动成为管理员。管理员签发配对码时可指定 `{"role":"admin"}`、`{"role":"member"}` 或 `{"role":"guest"}`，省略时仍默认普通设备；角色随一次性配对码存储，新设备不能在消费码或绑定时覆盖角色。游客和普通设备均不能修改自身角色。角色变更对现有凭据立即生效，刷新或重新绑定保留当前角色；修改角色会以 WebSocket 1012 触发重新连接和当前通知列表刷新。已经下发或复制的数据无法追溯收回。

通过 HTTP 降级或撤销最后一台有效管理员会返回 409，需先将另一台设备提升为管理员。权限复核、最后管理员检查和修改在同一数据库事务内完成，防止并发请求绕过限制。服务端本机恢复脚本仍可重置全部设备。

升级已有数据库时，所有已有设备一次性保留为管理员；之后新邀请默认普通设备。已有未消费邀请在升级后按普通设备加入，初始化码仍创建管理员。后续重启不会将已降级的设备重新提升。部署时先更新服务端，再更新客户端；旧客户端仍受服务端权限校验约束。

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
| `SESSION_NOTIFY_ACCESS_TTL_SECONDS` | `3600` | 访问令牌有效秒数 |
| `SESSION_NOTIFY_REFRESH_TTL_DAYS` | `90` | 刷新令牌有效天数 |
| `SESSION_NOTIFY_PAIR_CODE_TTL_SECONDS` | `300` | 已绑定设备签发的配对码有效秒数；本地初始化脚本使用默认五分钟 |
| `SESSION_NOTIFY_HOOK_TTL_HOURS` | `24` | 普通 Hook 通知有效小时数 |
| `SESSION_NOTIFY_PERMISSION_TTL_MINUTES` | `30` | 普通工具权限审批通知有效分钟数 |
| `SESSION_NOTIFY_DEVICE_PRESENCE_TTL_SECONDS` | `90` | Windows 在线状态有效秒数 |
| `SESSION_NOTIFY_EXPIRE_POLL_SECONDS` | `60` | 后台清理到期通知并广播过期事件的检查间隔 |

监听地址和端口由 `run_dev_server.ps1 -HostAddress ... -Port ...` 或 uvicorn 参数决定，`.env.example` 的 `SESSION_NOTIFY_HOST` 不被应用读取，`SESSION_NOTIFY_PORT` 只作为生成配对候选地址时的备用端口，两者均不控制监听。若通过 `-CertFile` 指定其他证书，还需把 `SESSION_NOTIFY_CERT_FILE` 指向同一文件，保证二维码指纹一致。

Linux / macOS 的脚本入口是 `scripts/generate_self_signed_cert.sh` 和 `scripts/run_dev_server.sh`。后者使用 `HOST_ADDRESS`、`PORT`、`CERT_FILE`、`KEY_FILE` 环境变量设置监听与 TLS，与上表的应用配置区分；自定义证书时同样需要设置 `SESSION_NOTIFY_CERT_FILE`。

## 手动发送测试通知

先从已绑定客户端取得一个新的配对码，再在服务端项目目录运行：

```powershell
uv run python scripts/send_test_notification.py --base-url https://127.0.0.1:8765 --pair-code "PASTE-PAIR-CODE" --all
uv run python scripts/send_test_notification.py --base-url https://127.0.0.1:8765 --stack 3
```

脚本将测试设备的访问令牌按地址缓存到 `runtime/.test_device.json`。缓存过期或设备被撤销后，需重新提供 `--pair-code`，不会自动匿名绑定或刷新令牌。服务端尚无设备时，可先用本地初始化命令取码。自签证书的校验豁免仅限回环地址；远程地址必须使用 HTTPS 和受信任证书。`--clear` 会确认该设备可见的全部活动状态通知，不限于测试通知。

## 测试

```powershell
uv run pytest
```

## 当前能力

- 设备绑定和 Bearer 令牌认证。
- 使用刷新令牌换发访问令牌；普通刷新不轮换刷新令牌，通过 `/api/v1/devices/bind` 重新绑定时才同时换发两种令牌。
- 通知创建、拉取、确认和过期；历史查询支持可见性/状态过滤、总数统计与游标分页，查询范围在服务端硬限制为最近 30 天。
- WebSocket 推送 `notification.created`、`notification.acknowledged`、`notification.expired`、`device.presence_changed`，配对成功通过 `pair.consumed` 仅通知签发设备；支持查询参数 `token` 或 `Authorization` 请求头，后者优先。
- 汇总 Windows 锁屏与通知暂停状态；Android 可按“未锁屏且未暂停”的电脑可用性决定是否展示提醒。
- 幂等确认：任一设备确认后，通知状态以服务端为准。
- Codex / Claude Code / Cursor / DeepSeek Harness Hook 载荷到统一通知的基础映射。
- `SESSION_NOTIFY_TAG` 作为 `metadata.tag` 随通知保存，供客户端展示和历史筛选。
- `SESSION_NOTIFY_PRIVACY_TAG`：`hide` 时所有设备下发的正文替换为 `***`；`local` 时仅来源设备看到明文。正文不可见时，元数据仅保留展示与关联控制字段，移除原始载荷、工具输入和自由文本诊断。服务端存储保持明文；不可见的正文不会进入历史关键词搜索。当前 Windows Hook bundle 15 已包含此能力。
- Codex 异步提问按来源设备、会话和完整题目指纹匹配回答，支持跨回合、逐题回答、重复投递和乱序补发；全部回答后持久确认并广播 `notification.acknowledged`。同题歧义时保留；迟到题目使原匹配产生歧义时，撤销未过期通知的自动确认，并通过原 ID 的 `notification.created` 更新两端，手动确认始终保留。Stop 和启动清理不消除未回答的异步问题。旧版引用回答按完整题目指纹唯一匹配；Hook bundle 15 的结构化回答进一步校验调用 ID 与题目序号，错误 ID 不回退为文本猜测。应先更新服务端，再更新 Hook。
- SQLite + WAL 本地存储。
- 自签名证书生成脚本和 Docker Compose 部署骨架。
- HTTPS/WSS 启动脚本，Compose 默认使用 `runtime/secrets/server.crt` 和 `server.key`。
- [OpenAPI 快照](protocol/openapi.yaml)和 [WebSocket 事件结构](protocol/ws-events.schema.json)供客户端对齐协议；运行时接口由 `app/main.py` 和 `app/schemas.py` 实现。

## 查询与协议维护

历史接口 `/api/v1/notifications/recent` 默认查询 1 天、每页 50 条，最多每页 100 条，时间范围上限为最近 30 天。支持重复 `status` / `level` 参数，以及机器、来源、标签和关键词过滤。游客范围和正文隐私在分页、计数及筛选建议前应用。30 天是查询窗口，不表示数据库定期删除全部旧数据。

`GET /api/v1/events` 有两种兼容行为：不传 `limit` 时使用原有事件补拉；传入 `limit=1..500` 时使用有界窗口，不传游标只返回最新事件 ID 作为基线。`cursor_found=false` 表示游标已不存在；客户端应结合最新活动通知快照恢复，而不是假定收到全部旧事件。

Hook 接口可能返回通知对象或 `null`。回答关联、工具完成信号、被策略抑制的事件不一定创建新通知；请求成功不等于一定出现弹窗。普通 Hook 通知默认 24 小时过期，确认类 Hook 默认使用 30 分钟有效期，具体判断以服务端映射为准。

修改协议时先核对路由、模型和相关测试，再更新本仓库 `protocol/`，并将两个协议文件同步到 Windows 与 Android 的同名目录，保持三份内容一致。说明文字使用中文，路径、字段名、枚举和实际生成的英文字符串保留原文。静态快照不直接参与运行时校验，不能仅改文档就宣称接口行为已改变。
