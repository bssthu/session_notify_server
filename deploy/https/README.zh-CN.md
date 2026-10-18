# 为 Session Notify 增加受信任的公网 HTTPS

HTTPS 网关把 Nginx、Certbot、续期调度、重试和 reload 放在同一个 `public-https` 容器中。启动网关就启动续期进程，无需另装 systemd 定时器。首次部署后端和更新流程见[部署总入口](../README.zh-CN.md)。

- 新适配器：`https://<HTTPS_PUBLIC_IP>:<HTTPS_PUBLIC_PORT>` → Nginx → 校验证书的 `https://server:<后端容器端口>`。
- 已有 Windows / Android 继续使用原后端入口及固定指纹，默认端口 8765。
- 公网 TCP 80 只服务 ACME HTTP-01 challenge；其他路径返回 404。
- 容器内部 9080 只提供公有证书元数据，不发布宿主机端口。后端通过管理员鉴权接口转交客户端。

HTTPS overlay 不创建第二个后端或数据库，不挂载 Docker socket，也不挂载原后端私钥。网关 master 与 Certbot 固定使用容器 UID:GID `0:0`，Nginx worker 保持非 root；首次签发和续期身份相同，并能继承旧证书文件的组权限。宿主机操作者的 `id -g` 或 `sg docker` 不再决定 Certbot 身份。证书、ACME 账户、重试状态均保留在 `runtime/public-https/`，不得加入 Git 或公开分享。

目标是 Linux Docker Compose v2；宿主机需 Bash、OpenSSL、curl、flock、timeout、ss、Python 3 和公有根证书包。网关镜像从固定 `nginx:1.30.5-alpine` 构建并安装 `certbot==5.8.0`，首次构建需要相应镜像仓库和 Python 包源。升级前应审查依赖并记录镜像 digest。

## 1. 准备

所有命令从服务端仓库根目录执行，使用有 Docker 权限的可信部署用户；需要时加 sudo。项目目录、脚本和会被 source 的配置必须由可信操作者管理。

公网 IP 必须由你管理；云安全组、防火墙和 NAT 需允许公网 TCP 80 及所选 HTTPS 端口。HTTP-01 每次续期仍需 80 可达，不能只在首次签发时开放。Docker 发布端口可能绕过常规 UFW 规则，应同时检查云安全组和 Docker 转发规则。

```sh
docker compose ps
# 从现有后端容器标签确认 Compose 项目名，不另建项目：
docker inspect <现有后端容器名> --format '{{ index .Config.Labels "com.docker.compose.project" }}'
mkdir -p runtime/public-https
chmod 700 runtime/public-https
cp deploy/https/env.example runtime/public-https/config.env
chmod 600 runtime/public-https/config.env
```

填写 `HTTPS_PUBLIC_IP`、`HTTPS_PUBLIC_PORT`（默认 443）、已有 `HTTPS_COMPOSE_PROJECT`、`HTTPS_UPSTREAM_TLS_NAME` 和宿主机的 `HTTPS_CA_BUNDLE`。ACME 邮箱填写 `HTTPS_ACME_EMAIL`；不使用邮箱时显式设 `HTTPS_ACME_REGISTER_WITHOUT_EMAIL=true` 并留空邮箱。

后端端口由根目录 `.env` 中的 `SESSION_NOTIFY_PORT` / `SESSION_NOTIFY_HOST_PORT` 配置。脚本解析 Compose 的实际端口，预检连接宿主机发布端口，Nginx 连接容器端口。HTTPS 工具不加载 `compose.override.yaml`，两套入口应共用 `.env` 配置。

`HTTPS_UPSTREAM_TLS_NAME` 必须是原证书的精确 DNS SAN，默认生成器提供 `localhost`。不能以关闭校验、仅匹配 CN 或重新生成原证书绕过预检。预检检查原证书、DNS SAN、实际后端证书指纹，只把公有证书复制到网关的 upstream 目录。

```sh
bash deploy/https/manage.sh preflight
```

## 2. 首次签发与激活

```sh
bash deploy/https/manage.sh bootstrap
```

bootstrap 构建并启动网关及续期进程；没有生产证书时只开放 HTTP challenge，不自动接受 CA 条款或执行首次签发。它拒绝覆盖已有网关配置。先从外网验证 challenge 路径可达；可在 `runtime/public-https/webroot/.well-known/acme-challenge/` 下放置自己的临时探针，检查后移除该探针。

签发会向 Let's Encrypt 发送 IP、证书请求和所填邮箱，正式证书会进入公开证书透明度日志。操作者需阅读并同意[订户协议](https://letsencrypt.org/repository/)，再执行带显式同意参数的命令：

```sh
bash deploy/https/manage.sh test-issuance --accept-le-terms
bash deploy/https/manage.sh issue --accept-le-terms
bash deploy/https/manage.sh activate
bash deploy/https/manage.sh verify
# 从外部网络执行，保留正常 TLS 校验：
curl --fail --show-error https://<HTTPS_PUBLIC_IP>:<HTTPS_PUBLIC_PORT>/health
```

staging 使用独立账户、证书目录和限流状态；Nginx 配置只引用生产 lineage。激活先验证公有信任链、IP 身份和有效期，再测试配置、reload，并比对实际加载指纹和 `/health`。签发失败时 HTTP challenge 和原后端入口仍可用。

## 3. 自动续期、日志与管理员 WARNING

续期进程随网关启动，并在网关退出时结束；任一进程异常退出会结束整个容器，由 `restart: unless-stopped` 恢复。启动前检查持久化目录可写。常规每六小时检查一次，Certbot 自行判断是否需要换证；失败采用 15 分钟起步、最高六小时的退避。

CA 的错误响应 `Retry-After` 支持秒数和 HTTP 日期，同时识别错误详情中的 UTC `retry after`；取最晚时间并保留边界余量。遇到限流但没有可解析时间时保守等待六小时。生产限流状态持久化在 `work/gateway-ca-backoff.json`，重启、重建、手动续期都不会绕过它。正常 ACME 轮询响应的 `Retry-After` 不影响下一次续期调度。参考 [CA 限流规则](https://letsencrypt.org/docs/rate-limits/#retrying-after-hitting-rate-limits)。

CA 暂时不可用或仍在限流时，也会尝试验证、加载磁盘已有的新证书；只有公有 CA/IP 校验通过才 reload，并继续核对实际握手指纹与健康接口。手动检查复用同一把进程锁、权限和 CA 退避：

```sh
bash deploy/https/manage.sh renew
bash deploy/https/manage.sh compose ps public-https
bash deploy/https/manage.sh compose logs --tail 100 public-https
bash deploy/https/manage.sh verify
```

续期失败只写日志，不发邮件或服务端通知。`verify` 在证书剩余不足 48 小时时仍返回失败，供维护时判断。Nginx 不记录携带 WebSocket token 的请求日志；不要公开 Certbot 调试日志、账户或私钥。

后端 `GET /api/v1/server/certificates` 仅允许有效管理员访问，返回后端启动时的证书元数据、网关当前实际加载的公网证书和服务端时间。Compose 默认使用内部 `http://public-https:9080/status`；独立部署后端时可设置 `SESSION_NOTIFY_GATEWAY_STATUS_URL` 为可达的内部地址。该端口不要发布到公网。

Windows / Android 管理员客户端在后台检查或同步时，发现证书剩余时间严格小于 48 小时（包含已过期）就弹出本地 WARNING。按绑定、证书和临期/过期阶段去重，记录跨重启保留；证书恢复或权限取消后清除旧提醒。网关暂时不可达不代表已恢复。普通设备不读取该接口。提示依赖管理员客户端运行及其通知权限，并非额外的服务端告警系统。

## 4. 配对与原后端证书

配对响应中的 `server_fingerprint` 仍是原后端自签证书的指纹。已有 Windows / Android 保留原入口及指纹，不把短期公网证书写入旧绑定。新自动化客户端使用正常公有 CA 校验，独立配对并保存自己的凭据；不要借用管理员 token 或关闭 TLS 校验。

网关不自动轮换原后端自签证书，避免破坏固定指纹。它的到期也会触发管理员 WARNING，轮换仍需单独协调客户端信任。

## 5. 从旧定时器方案迁移

保留现有 `runtime/public-https` 及原后端数据库、证书和设备凭据。计划部署时先停止实际安装的旧定时器及正在运行的续期服务（按原作用域选择）：

```sh
# 用户级旧部署：
systemctl --user disable --now session-notify-https-renew.timer
systemctl --user stop session-notify-https-renew.service
# 系统级旧部署使用 sudo systemctl 的对应命令。
```

然后在新代码上构建/重建网关，已有正式证书无需重新接受条款或首次签发：

```sh
bash deploy/https/manage.sh compose up -d --build --no-deps public-https
bash deploy/https/manage.sh renew
bash deploy/https/manage.sh activate
bash deploy/https/manage.sh verify
```

需要后端同时获得管理员状态接口时，按部署总入口更新后端，或在干净工作区执行 `bash deploy/update-server.sh --https`。旧 timer 尚未移除时，其 `manage.sh renew` 也会转交网关并遵守共享锁与 CA 退避，但应停用旧任务避免多余检查。旧实现没有保存的 CA 限流截止时间无法自动迁移；应先根据现有日志等待 CA 允许的重试时间，再进行恢复。

## 6. 后续更新和停用

`bash deploy/update-server.sh --https` 构建网关、更新后端及网关，再激活并验证入口；无需安装额外服务。只更新应用时，已有网关继续管理续期。修改公网端口后需重建网关端口映射；仅 reload 不改变 Docker 端口。

仅停用 HTTPS 网关及其续期进程：

```sh
bash deploy/https/manage.sh compose stop public-https
```

保留 `runtime/public-https` 以便恢复，不执行 `down -v`、删除数据库卷或重新生成原后端证书。恢复网关时会继续使用持久化的 CA 退避状态。可重复测试与目标环境验收边界见[部署测试说明](../../tests/deploy/README.md)。
