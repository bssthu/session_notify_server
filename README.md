# Session Notify 服务端

基于 FastAPI 与 SQLite，将 Codex、Claude Code、Cursor、Devin、DeepSeek Harness 等工具的通知同步到多台设备。服务端是协议定义、设备权限、通知状态及事件关联的源头；客户端文档见 [Windows](../session_notify_windows/README.md) 和 [Android](../session_notify_android/README.md)。

本文按 2026-10-23 的仓库实现静态核对。需要 Python 3.11 或以上版本和 uv；应用依赖版本由 `uv.lock` 锁定。

## 升级兼容性

Codex 异步提问回答兼容旧版引用文本和 Hook bundle 15 的新版结构化格式。新版 `answered_batch` 使用调用 ID、题目序号及完整题目指纹关联，支持选项、自由输入、逐题和批量回答；一组题目全部回答后才同步确认通知。回答正文不上传，断网补发和服务端重启保留关联状态。部署时先更新服务端，再更新 Windows 客户端并执行 Hook「安装 / 更新」；旧版客户端和旧数据库继续兼容。

当前 Windows Hook bundle 为 **18**；文中 15、16 等数字表示功能引入版本。通知输入与发布限额由服务端执行，旧客户端同样可能收到 `413` / `422` / `429`。客户端升级后才具有旧 metadata 容错和可信“本机”标记处理；Android 需连同 Windows 共享 Web 资源重新构建。详见[输入与发布限额](#通知输入与发布限额)。

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

核对已有后端证书时，在服务器上只读运行 `openssl x509 -in runtime/secrets/server.crt -noout -fingerprint -sha256`，通过可信渠道将结果与客户端显示的实际 SHA-256 指纹比较；自定义证书路径须对应实际监听入口。Windows 的操作位置见[人工核对说明](../session_notify_windows/README.md#首次连接与更新)。无需重新生成证书。

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

Compose 默认使用 HTTPS 监听并发布 8765。在仓库根目录的 `.env` 中设置 `SESSION_NOTIFY_PORT` 可改变容器监听端口；`SESSION_NOTIFY_HOST_PORT` 可独立设置宿主机发布端口，省略时跟随监听端口。HTTPS 工具和更新脚本会读取 Compose 渲染后的端口配置，详见[部署与更新说明](deploy/README.zh-CN.md#配置后端端口)。Compose 挂载 `runtime/secrets/` 中的证书和私钥，数据库保存在 `session_notify_data` 命名卷中。初始化和重置命令应通过 `docker compose exec server` 在容器内执行，使用 `/data/session_notify.db`；宿主机默认的 `runtime/session_notify.db` 是另一个数据库。构建通过 `uv sync --frozen --no-dev` 使用 `uv.lock` 中的应用依赖版本。

Linux 首次部署、日常更新和旧更新脚本迁移见 [部署与更新说明](deploy/README.zh-CN.md)。需要系统受信任证书的调用端，可按 [公网 HTTPS 部署说明](deploy/https/README.zh-CN.md) 增加独立 Nginx/Certbot 入口；对外端口通过 `HTTPS_PUBLIC_PORT` 配置，默认 443，原客户端保留已有后端地址和原证书指纹。

公网 HTTPS 网关内置续期进程，首次签发和续期使用固定容器身份，无需额外 systemd timer；CA 限流截止时间跨容器重启保留。失败只写网关日志。管理员客户端通过 `GET /api/v1/server/certificates` 检查网关实际加载证书及后端证书的有效期，严格不足 48 小时或已过期时显示本地 WARNING；接口对普通设备和游客返回 403。

## 刷新令牌有效期与恢复

- 首台管理员永久有效；其他新绑定默认 90 天。管理员签发配对码或修改设备时可选择 `refresh_ttl_days`（1–36500 天）或带时区的 `refresh_expires_at`，二者不能同时提供；任意字段显式 `null` 表示永久。邀请省略则默认，PATCH 省略则不变。相对邀请期限从成功绑定时计算；绝对日期已到期的码不能消费。
- 只有当前有效管理员能修改任意设备的刷新期限，包括为已到期但未撤销的设备延期。普通设备/游客不能修改自己的期限；自助重绑轮换凭据但保留原期限，过期凭据不能自助续期。撤销设备不可通过延期恢复。
- 绑定、刷新、设备列表及修改响应均返回 `refresh_expires_at`、`access_expires_at`；绑定和刷新还返回 `server_time`。新 access 不晚于 refresh 到期；缩短 refresh 立即收紧现有 access，延长 refresh 不延长旧 access。
- 只剩一台可用管理员时，其 refresh 自动变为永久。多台有限期管理员允许共存；在倒数第二台到期时保护最后存活者。服务闲置跨过多个期限或同时到期时，以最晚期限、创建时间、设备 ID 确定唯一存活者；只保护该未撤销管理员，其他过期设备不恢复。启动迁移、身份检查、管理事务与定期检查均执行此规则。设置最后可用管理员为有限期返回 409 / `last_admin_must_be_permanent`。降级、撤销和并发期限修改使用同一 SQLite 写事务复核。
- HTTP 401 的 `detail` 为 `{code,message,server_time}`。`access_token_expired` 可刷新后重试一次；业务请求的 `invalid_token` 也可能只是旧 access 被轮换，先尝试一次共享刷新。refresh 返回 `refresh_token_expired` 时保留凭据，停止普通请求和业务 WebSocket，每小时只重试一次 refresh；管理员延期后同一 refresh 可恢复。refresh 返回 `invalid_token` 或 `device_revoked` 才进入重新配对流程。
- WebSocket 在连接、广播和空闲检查中复核两类期限；授权失效关闭 1008（reason 尽可能为上述 code）。角色/期限更新关闭 1012，客户端应重新检查凭据和期限后再连接。

## 配置

服务从进程环境读取应用配置；`.env.example` 不会被启动脚本自动加载。PowerShell 中使用 `$env:变量名 = "值"`，Compose 部署则在 `compose.yaml` 的 `environment` 或本机 override 中配置。Compose 会自动读取仓库根目录的 `.env` 用于配置插值，后端端口在此设置；其他变量只有被 Compose 的 `environment` 引用或显式传入容器时才成为应用配置。

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SESSION_NOTIFY_DB` | `runtime/session_notify.db` | SQLite 数据库路径；Compose 覆盖为 `/data/session_notify.db` |
| `SESSION_NOTIFY_PORT` | `8765` | Compose 容器监听端口；直接启动应用时仅作为配对候选地址的备用端口 |
| `SESSION_NOTIFY_HOST_PORT` | 跟随 `SESSION_NOTIFY_PORT` | Compose 宿主机发布端口 |
| `SESSION_NOTIFY_PAIR_MODE` | `strict` | 新设备配对门禁 |
| `SESSION_NOTIFY_CERT_FILE` | `runtime/secrets/server.crt` | 配对二维码所需的服务端证书指纹来源 |
| `SESSION_NOTIFY_GATEWAY_STATUS_URL` | 空；Compose 默认 `http://public-https:9080/status` | 网关实际加载证书的内部状态地址；空值禁用网关查询，不影响后端证书查询 |
| `SESSION_NOTIFY_ACCESS_TTL_SECONDS` | `7200` | 访问令牌有效秒数，默认 2 小时 |
| `SESSION_NOTIFY_REFRESH_TTL_DAYS` | `90` | 默认新设备刷新令牌有效天数（管理员可覆盖） |
| `SESSION_NOTIFY_PAIR_CODE_TTL_SECONDS` | `300` | 已绑定设备签发的配对码有效秒数；本地初始化脚本使用默认五分钟 |
| `SESSION_NOTIFY_HOOK_TTL_HOURS` | `24` | 普通 Hook 通知有效小时数 |
| `SESSION_NOTIFY_PERMISSION_TTL_MINUTES` | `30` | 普通工具权限审批通知有效分钟数 |
| `SESSION_NOTIFY_DEVICE_PRESENCE_TTL_SECONDS` | `90` | Windows 在线状态有效秒数 |
| `SESSION_NOTIFY_EXPIRE_POLL_SECONDS` | `60` | 后台清理到期通知并广播过期事件的检查间隔 |
| `SESSION_NOTIFY_PUBLISH_PER_MINUTE` | `600` | 每台认证设备每分钟允许发布的通知 / Hook 请求数，正整数 |
| `SESSION_NOTIFY_PUBLISH_BYTES_PER_DAY` | `67108864` | 每台认证设备每日通知 / Hook 载荷预算，默认 64 MiB，正整数 |

直接启动时，监听地址和端口由 `run_dev_server.ps1 -HostAddress ... -Port ...` 或 uvicorn 参数决定；`SESSION_NOTIFY_HOST` 不被应用读取，`SESSION_NOTIFY_PORT` 不替代这些启动参数。Compose 则通过上述端口变量配置 uvicorn 和端口映射。若通过 `-CertFile` 指定其他证书，还需把 `SESSION_NOTIFY_CERT_FILE` 指向同一文件，保证二维码指纹一致。

两小时 access token 为每小时执行的任务留出调度余量，但任务仍应根据 `access_expires_at` 提前刷新，或在 401 后刷新并重试一次。新默认值只影响后续签发/刷新的 token；已有 token 的到期时间不会被修改。refresh 默认 90 天，由管理员管理；首台及最后可用管理员永久。每次刷新会立即使该设备的旧 access token 失效，因此自动化调用端应独立配对。

Linux / macOS 的脚本入口是 `scripts/generate_self_signed_cert.sh` 和 `scripts/run_dev_server.sh`。后者使用 `HOST_ADDRESS`、`PORT`、`CERT_FILE`、`KEY_FILE` 环境变量设置监听与 TLS，与上表的应用配置区分；自定义证书时同样需要设置 `SESSION_NOTIFY_CERT_FILE`。Shell 证书生成器需要支持 `req -addext` 的 OpenSSL，默认 SAN 为 `DNS:localhost, IP:127.0.0.1`；PowerShell 生成器另外包含 `IP:10.0.2.2`。两个生成器都会写入指定输出目录，不能用重新运行生成器代替已有证书的检查。

## 通知输入与发布限额

应用自身限制 POST / PUT / PATCH / DELETE 请求体为 **256 KiB**，超过返回 `413 / request_too_large`；应用读取请求体最多等待 15 秒，超时返回 `408`。直连 Uvicorn 和经网关访问均生效。通知 `metadata` 和完整 Hook 输入（包含额外字段）各自按紧凑 JSON 的 UTF-8 编码限制为 **64 KiB**、嵌套深度 **8**（根为 0）、总值数 **4096**（包含根、容器和叶值，不另计对象键）；Hook 生成或去重合并后的 metadata 也会检查。超出或类型不符返回 `422`。`kind`、标签、事件名称、工具名称等控制字段（含 `raw` 内同名字段）只接受字符串、数字、布尔值或 null，`tool_input` 等结构化字段仍可使用对象和数组。

`POST /api/v1/notifications` 和 `POST /api/v1/hooks/{source}` 共享每设备限额，适用于所有角色，按 UTC 自然分钟 / 自然日计数；字节数以通过模型校验后的完整 JSON 为准。通过入口校验、鉴权和额度检查的重试、重复投递及被通知策略抑制的 Hook 也计入；后续业务处理失败不退还额度。入口拒绝的 `413` / `422` 以及额度拒绝的 `429` 不增加计数。计数存于 SQLite，重启和共享同一数据库的多进程不会重置。超过请求数返回 `429 / publish_rate_limited`，超过日字节预算返回 `429 / publish_daily_quota`，`Retry-After` 表示距相应窗口结束的秒数。调用端应延迟重试；查询和确认通知不受发布额度影响。上述两个环境变量可通过 Compose `.env` 调整，修改后需重新创建后端容器，见[部署配置](deploy/README.zh-CN.md#配置发布限额)。

错误响应并非统一格式：应用的 `413`、`429` 及生成/合并 metadata 的 `422` 使用 `detail: {code, message}`；入口模型校验的 `422` 使用 FastAPI 的 `detail` 数组。应用的 `408` 使用字符串 `detail`；前置网关先拒绝请求时也可能返回其他格式。调用端应先按 HTTP 状态分类，不要假设每次都存在 `detail.code`。`413` / `422` 需修正载荷后再投递，持续重发相同内容不会解决。当前 Bridge 与 Codex 失败队列的重试策略不同，见[Bridge 说明](../session_notify_windows/hook_bridge/README.md#输入拒绝与限流处理)。

限额用于控制写入速率，不是数据库总容量上限，也不会删除历史记录。磁盘仍需按保留需求管理。服务端会从新通知及旧记录的下发副本移除 `local_only`、`countdown_local`、`alarm_local`、`controllable`、`alarm_preview` 等仅供客户端本机使用的标记（包括 camelCase 形式）；本机来源由服务端认证的 `origin_device_id` 或客户端自身创建的本地通知决定。

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

部署脚本的独立 Linux 离线测试及上线验收见 [部署测试说明](tests/deploy/README.md)。

## 当前能力

- 设备绑定和 Bearer 令牌认证。
- 使用刷新令牌换发访问令牌；普通刷新不轮换刷新令牌，通过 `/api/v1/devices/bind` 重新绑定时才同时换发两种令牌。
- 通知创建、拉取、确认和过期；历史查询支持可见性/状态过滤、总数统计与游标分页，查询范围在服务端硬限制为最近 30 天。
- WebSocket 推送 `notification.created`、`notification.acknowledged`、`notification.expired`、`device.presence_changed`，配对成功通过 `pair.consumed` 仅通知签发设备；支持查询参数 `token` 或 `Authorization` 请求头，后者优先。
- 汇总 Windows 锁屏与通知暂停状态；Android 可按“未锁屏且未暂停”的电脑可用性决定是否展示提醒。
- 幂等确认：任一设备确认后，通知状态以服务端为准。
- Codex / Claude Code / Cursor / Devin / DeepSeek Harness Hook 载荷到统一通知的基础映射。
- `SESSION_NOTIFY_TAG` 作为 `metadata.tag` 随通知保存，供客户端展示和历史筛选。
- `SESSION_NOTIFY_PRIVACY_TAG`：`hide` 时所有设备下发的正文替换为 `***`；`local` 时仅来源设备看到明文。正文不可见时，元数据仅保留展示与关联控制字段，移除原始载荷、工具输入和自由文本诊断。服务端存储保持明文；不可见的正文不会进入历史关键词搜索。Windows Hook 自 bundle 11 支持此能力。
- Codex 异步提问按来源设备、会话和完整题目指纹匹配回答，支持跨回合、逐题回答、重复投递和乱序补发；全部回答后持久确认并广播 `notification.acknowledged`。同题歧义时保留；迟到题目使原匹配产生歧义时，撤销未过期通知的自动确认，并通过原 ID 的 `notification.created` 更新两端，手动确认始终保留。Stop 和启动清理不消除未回答的异步问题。旧版引用回答按完整题目指纹唯一匹配；Hook bundle 15 的结构化回答进一步校验调用 ID 与题目序号，错误 ID 不回退为文本猜测。应先更新服务端，再更新 Hook。
- SQLite + WAL 本地存储。
- 自签名证书生成脚本和 Docker Compose 部署骨架。
- HTTPS/WSS 启动脚本，Compose 默认使用 `runtime/secrets/server.crt` 和 `server.key`。
- [OpenAPI 快照](protocol/openapi.yaml)和 [WebSocket 事件结构](protocol/ws-events.schema.json)供客户端对齐协议；运行时接口由 `app/main.py` 和 `app/schemas.py` 实现。

## 查询与协议维护

历史接口 `/api/v1/notifications/recent` 默认查询 1 天、每页 50 条，最多每页 100 条，时间范围上限为最近 30 天。支持重复 `status` / `level` 参数，以及机器、来源、标签和关键词过滤。游客范围和正文隐私在分页、计数及筛选建议前应用。30 天是查询窗口，不表示数据库定期删除全部旧数据。

`GET /api/v1/events` 有两种兼容行为：不传 `limit` 时使用原有事件补拉；传入 `limit=1..500` 时使用有界窗口，不传游标只返回最新事件 ID 作为基线。`cursor_found=false` 表示游标已不存在；客户端应结合最新活动通知快照恢复，而不是假定收到全部旧事件。

Hook 接口可能返回通知对象或 `null`。回答关联、工具完成信号、被策略抑制的事件不一定创建新通知；请求成功不等于一定出现弹窗。当前 Hook 有效期按最终标题判断：标题包含区分大小写的 `needs confirmation` 时默认 30 分钟，否则默认 24 小时，分别由 `SESSION_NOTIFY_PERMISSION_TTL_MINUTES` 和 `SESSION_NOTIFY_HOOK_TTL_HOURS` 覆盖。因此自定义标题也会影响有效期，不能只根据消息等级或原始事件类型推断。

修改协议时先核对路由、模型和相关测试，再更新本仓库 `protocol/`，并将两个协议文件同步到 Windows 与 Android 的同名目录，保持三份内容一致。说明文字使用中文，路径、字段名、枚举和实际生成的英文字符串保留原文。静态快照不直接参与运行时校验，不能仅改文档就宣称接口行为已改变。
