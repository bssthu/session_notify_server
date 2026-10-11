# 为 Session Notify 增加受信任的公网 HTTPS

此可选部署方案增加 Nginx 入口和一次性 Certbot 容器。首次部署后端和更新流程见[部署总入口](../README.zh-CN.md)。拓扑：

- 新适配器：`https://<HTTPS_PUBLIC_IP>:<HTTPS_PUBLIC_PORT>` → Nginx → **校验证书的** `https://server:<后端容器端口>`
- 原 Windows / Android：继续使用后端发布端口（默认 8765），证书指纹、配对和凭据不变；主动更改发布端口时需协调客户端地址
- TCP 80：只提供 ACME HTTP-01 challenge，其他请求返回 404，不转发 API

HTTPS overlay 不修改原 `compose.yaml`、数据库卷、原证书或私钥，不启动第二个应用进程，也不迁移数据库。项目目录、部署脚本和配置须由可信操作者管理；启用 root 定时器前，应确保普通不可信用户不能修改这些文件（尤其是会被 source 的 config.env）。目标是 Linux Docker Compose v2；宿主机需要 Bash、OpenSSL、curl、flock、timeout、ss、Python 3 和系统公有根证书包。Python 用于解析 Compose 端口及生成 systemd 配置，无第三方运行依赖。

后端端口统一由仓库根目录 `.env` 的 `SESSION_NOTIFY_PORT` / `SESSION_NOTIFY_HOST_PORT` 配置，见[后端端口说明](../README.zh-CN.md#配置后端端口)。管理脚本解析 `docker compose config --format json`：预检连接 `127.0.0.1:<发布端口>`，Nginx 连接 `server:<容器监听端口>`。不会把端口另存到 HTTPS 配置中。预检证书仍读取仓库内 `runtime/secrets/server.crt`。`HTTPS_PUBLIC_PORT` 只改变新增公网入口；更新工具的健康检查覆盖参数也不会覆盖这些后端配置。HTTPS 工具不加载 `compose.override.yaml`，后端端口应通过共同的 `.env` 配置。

## 1. 准备与确认

先将服务端仓库更新到包含 `compose.https.yaml` 和本目录的版本。以下命令均从仓库根目录执行；已有后端应正常运行。选择系统级（root）或用户级部署，始终用同一用户管理该入口。下文默认系统级；用户级方式见第 3 节。

先确认你能管理实际配置的固定公网 IP，IP 不属于共享反向代理；云安全组、宿主机防火墙、NAT 需允许公网 TCP **80 和所选 HTTPS 端口** 到这台 Docker 主机。80 以后每次续期都要可达，所选 HTTPS 端口是新客户端入口。Docker 发布端口可能不受 UFW 的常规规则约束，也要核对云安全组。原后端入口保持现状。不要为此停掉已有网站或其他容器；80 或所选 HTTPS 端口若占用，应先决定如何整合现有反向代理，管理脚本会检查本机监听，Docker 仍可能检测到额外的发布端口冲突。

查明正在运行的原容器及项目名（只读）：

```sh
docker ps --format 'table {{.Names}}\t{{.Ports}}'
docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' 原服务容器名
openssl x509 -in runtime/secrets/server.crt -noout -subject -ext subjectAltName -fingerprint -sha256
```

准备配置，填写实际公网 IPv4、项目名、HTTPS 端口和联系邮箱（也支持明确选择无邮箱注册）。真实地址只写入被 Git 忽略的 `runtime/public-https/config.env`，不要写回 `env.example`。下文 `<HTTPS_PUBLIC_IP>` 和 `<HTTPS_PUBLIC_PORT>` 是占位符，不是可访问的地址；执行命令前，须将它们连同尖括号替换为自己配置的公网 IP 和端口：

```sh
sudo install -d -m 700 runtime/public-https
sudo install -m 600 deploy/https/env.example runtime/public-https/config.env
sudoedit runtime/public-https/config.env
sudo bash deploy/https/manage.sh preflight
```

`HTTPS_PUBLIC_PORT` 是对外 HTTPS 端口，默认 443，可设置为 8443 等 1–65535 内的空闲端口（不能为 ACME 使用的 80）。`manage.sh` 将同一数值用于 Compose 映射、端口冲突检查、TLS 握手和健康检查。Nginx 容器内部继续监听 443，这是内部实现，不限制对外端口。证书绑定 IP 身份，不绑定端口。8443 仅为配置示例；外网访问命令中的 `<HTTPS_PUBLIC_PORT>` 须替换为实际配置值。

公网 TCP 80 必须保持可达，因为此方案使用 ACME HTTP-01；改变 `HTTPS_PUBLIC_PORT` 不会改变 CA 的验证端口。

按需填写邮箱，或明确选择无邮箱注册：

```sh
HTTPS_PUBLIC_PORT=8443
HTTPS_ACME_EMAIL=
HTTPS_ACME_REGISTER_WITHOUT_EMAIL=true
```

无邮箱仅影响 ACME 账户联系信息，不影响证书有效性。两种注册方式均需按下文显式接受 CA 条款。

更改已部署入口的 `HTTPS_PUBLIC_PORT` 后，先运行 `sudo bash deploy/https/manage.sh compose up -d --no-deps public-https` 更新宿主机端口映射，再执行 `verify` 并从外部网络验收；仅 reload Nginx 不会改变 Docker 端口映射。

`HTTPS_COMPOSE_PROJECT` 必须与运行中容器标签一致，不能另起项目名，否则会指向不同网络/数据库。后续脚本只创建 `public-https`，始终 `--no-deps`，不会重建 `server`。

`HTTPS_UPSTREAM_TLS_NAME` 必须填写原证书的一个**精确 DNS SAN**。仓库默认生成 `DNS:localhost, IP:127.0.0.1`，此时填 `localhost`，不要填 Docker 服务名 `server`。原脚本若把公网 IP 写入 DNS SAN，填写该 DNS SAN 字符串即可。只有 `IP Address:...` 而没有匹配 DNS SAN 的证书不适用此 Nginx 主机名验证方案，预检会停止。不要用关闭校验、仅看 CN 或重生成原证书来绕过。

预检通过 OpenSSL 检查证书时间/链、DNS SAN、运行中后端发布端口的实际证书指纹，并只复制原**公有证书**到 `runtime/public-https/upstream/server.crt`。原私钥不复制、不挂载给新容器。若实际使用私有 CA 链或非默认 TLS 部署而预检失败，先人工审查，不要盲目继续。

## 2. 无证书启动、测试与正式签发

```sh
sudo bash deploy/https/manage.sh bootstrap
```

此时只服务 80 challenge；所选 HTTPS 端口尚无 TLS 监听，这是正常的。可以在服务器创建临时探针，再从**另一条外部网络**检查：

```sh
sudo mkdir -p runtime/public-https/webroot/.well-known/acme-challenge
printf 'acme-reachability-ok\n' | sudo tee runtime/public-https/webroot/.well-known/acme-challenge/probe >/dev/null
# 在另一台外部机器运行，应返回 acme-reachability-ok：
curl --fail "http://<HTTPS_PUBLIC_IP>/.well-known/acme-challenge/probe"
# 测试后在服务器删除自己创建的探针：
sudo rm runtime/public-https/webroot/.well-known/acme-challenge/probe
```

签发命令会将联系邮箱（若提供）、IP 及证书请求发给 Let's Encrypt，并接受其当前[订户协议/服务条款](https://letsencrypt.org/repository/)；正式证书的 IP 会进入公开证书透明度日志。仅在操作者读过并同意后执行带 `--accept-le-terms` 的命令。管理脚本不替你接受或创建账户。

先可选测试，再正式签发：

```sh
sudo bash deploy/https/manage.sh test-issuance --accept-le-terms
sudo bash deploy/https/manage.sh issue --accept-le-terms
sudo bash deploy/https/manage.sh activate
```

测试使用独立 staging 目录与账户，Nginx 没有挂载该目录。`issue` 明确使用生产 ACME 地址。激活前还会用宿主机公有 CA 包校验生产证书链和 IP，staging、自签、过期、错误 IP 均不会装载。

没有证书时不生成假的临时生产证书；签发失败保持 80 challenge 和原后端入口可用。`bootstrap` 拒绝覆盖已有前门配置。若 bootstrap 因端口占用失败，先解决冲突，再运行：

```sh
sudo bash deploy/https/manage.sh compose up -d --no-deps public-https
```

正式激活只替换新增 Nginx 配置，先 `nginx -t` 再 reload。测试失败恢复前一份配置，不给运行中 Nginx 发送 reload。随后比较所选 HTTPS 端口握手拿到的证书与新证书指纹，并验证 HTTPS `/health`；只看 Certbot 返回成功或 reload 信号成功是不够的。

## 3. 验收与自动续期

```sh
sudo bash deploy/https/manage.sh verify
# 另一个外部网络上运行；不使用 -k/--insecure：
curl --fail --show-error "https://<HTTPS_PUBLIC_IP>:<HTTPS_PUBLIC_PORT>/health"
```

本机 verify 使用公网 IP 身份校验，但连接本机所选 HTTPS 端口；它不代替外网路由/防火墙验收。然后让新适配器使用包含实际端口的完整地址（格式为 `https://<HTTPS_PUBLIC_IP>:<HTTPS_PUBLIC_PORT>`，须替换占位符），保持正常系统 TLS 校验，并按原配对流程获得自己的设备凭据。健康检查成功不代表配对或发送通知已完成。

Let's Encrypt 的 IP 证书有效期仅 **160 小时**，必须启用并监测续期。Certbot 会自行判断续期时机，定时器每 6 小时检查一次并加 0–20 分钟随机延迟。不是每次检查都签发。

系统级部署：生成器根据当前仓库绝对路径渲染 `.service.in` 模板，将结果写到被忽略的运行目录，处理路径中的空格及 systemd 特殊字符。它不安装或启动服务；不要直接安装或修改模板。先生成并核对，再安装：

```sh
sudo python3 deploy/https/render_systemd.py --scope system
sudo cat runtime/public-https/systemd/system/session-notify-https-renew.service
sudo install -m 644 runtime/public-https/systemd/system/session-notify-https-renew.service /etc/systemd/system/
sudo install -m 644 runtime/public-https/systemd/system/session-notify-https-renew.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/session-notify-https-renew.service /etc/systemd/system/session-notify-https-renew.timer
sudo systemctl daemon-reload
sudo systemctl enable --now session-notify-https-renew.timer
sudo systemctl start session-notify-https-renew.service
sudo systemctl list-timers session-notify-https-renew.timer
sudo journalctl -u session-notify-https-renew.service -n 60 --no-pager
```

### 使用已有 Docker 权限的普通用户部署

脚本也支持普通部署用户，不要求 sudo。若选择此方式，上文创建配置和运行 `manage.sh` 的命令去掉 `sudo`，始终由同一个部署用户执行。配置目录仍须限制为 700，配置文件为 600。Certbot 容器按调用者的 UID/GID 写入证书目录，避免产生只能由 root 续期的文件。不要混用 root 和普通用户部署同一份状态。

使用用户级定时器时，应先确认 `loginctl show-user "$USER" -p Linger` 返回 `Linger=yes`，保证退出 SSH 后及重启时仍运行；否则请管理员启用 linger，或使用上面的系统级方案。生成当前仓库对应的用户 unit 后核对并安装：

```sh
python3 deploy/https/render_systemd.py --scope user
cat runtime/public-https/systemd/user/session-notify-https-renew.service
install -d -m 700 "$HOME/.config/systemd/user"
install -m 644 runtime/public-https/systemd/user/session-notify-https-renew.service "$HOME/.config/systemd/user/"
install -m 644 runtime/public-https/systemd/user/session-notify-https-renew.timer "$HOME/.config/systemd/user/"
systemd-analyze --user verify "$HOME/.config/systemd/user/session-notify-https-renew.service" "$HOME/.config/systemd/user/session-notify-https-renew.timer"
systemctl --user daemon-reload
systemctl --user enable --now session-notify-https-renew.timer
systemctl --user start session-notify-https-renew.service
systemctl --user list-timers session-notify-https-renew.timer
journalctl --user -u session-notify-https-renew.service -n 60 --no-pager
```

只有正式签发和激活完成后再开启定时器。续期成功的 deploy hook 留下标记，宿主机执行校验/reload；容器没有 Docker socket。证书未到期时不无故 reload。若上次签发成功而 reload 失败，下次会比较磁盘/实际加载指纹并重试。Certbot 失败时不会 reload；原服务仍不变。

日志出现 `Local HTTPS port <端口> trust, IP identity, loaded certificate and /health verified` 才代表本次加载验证完成。可做续期挑战演练，不会把 staging 证书切到生产：

```sh
sudo bash deploy/https/manage.sh compose run --rm --no-deps public-certbot renew --cert-name session-notify-public --dry-run
```

将 systemd 失败、外部 HTTPS `/health` 失败、证书剩余不足 48 小时接入你现有的告警；管理脚本不会自动给你发邮件或创建告警服务。脚本在实际加载证书不足 48 小时时返回失败，须及时处理。不要等过期邮件。Nginx 为避免记录 WebSocket 查询参数中的 token，关闭请求日志并只输出严重错误；开启调试日志前先处理脱敏。

## 4. 配对与证书固定注意事项

原服务配对响应中的 `server_fingerprint` 仍来自后端的自签证书。它**不是**公网 HTTPS 入口的证书指纹。Windows/Android 的全证书指纹固定也无法透明承受每几天自动换证书。

因此已有客户端继续使用原后端入口，不能只将地址改成公网 HTTPS 入口或把新证书指纹写进旧客户端。新自动化适配器应使用公有 CA 校验，独立保存自己的配对/刷新凭据，不禁用 TLS 校验，不使用其他设备的 token。若未来要让原客户端全面迁到公网 HTTPS 入口，需另行改造配对元数据和客户端信任策略，不在本部署方案范围内。

### 自动化客户端的凭据使用

为自动化客户端单独配对，保存自己的 `device.id`、`refresh_token`、`access_token`、`access_expires_at` 和完整 HTTPS 地址（包含自定义端口）。当前协议的 `platform` 只接受 `windows` 或 `android`；云端适配器可使用 `windows` 并取独立设备名，不要上报虚假的桌面解锁状态。新设备可使用普通设备权限，无需借用管理员 token。

访问令牌默认有效期为 7200 秒（2 小时），环境变量 `SESSION_NOTIFY_ACCESS_TTL_SECONDS` 可覆盖。每小时任务应在运行时检查 `access_expires_at`，剩余不足一小时则通过 `POST /api/v1/auth/refresh` 换取新 token 并持久保存；业务请求如返回 401，可刷新后重试一次。刷新失败应报告需要重新配对。refresh token 为 90 天，刷新不会延长它的到期时间。

刷新会立即替换该设备旧 access token。不要让其他设备共用这组凭据；同一适配器的并发任务应串行刷新并原子保存新 token。不要记录 token、把凭据加入 Git，或把 2 小时有效期当成调度一定准时的保证。升级服务不会追溯延长已经签发的 token；后续配对或刷新才获得新的有效期。

验收顺序为：客户端正常校验证书访问 `/health` → 消费独立配对码 → 带 Bearer token 调用 API → 刷新并保存新 token → 旧 token 返回 401、新 token 可以继续调用。需要发送测试通知时，使用独立会话标识，避免与真实任务通知混淆。

原自签证书仍会到期；管理脚本不轮换它，以免破坏现有固定指纹。原证书到期会使代理安全地返回错误，也会影响旧客户端，需另行规划协调轮换。

## 5. 回滚

只停新增前门和定时器，原后端服务、数据库和证书不动：

```sh
sudo systemctl disable --now session-notify-https-renew.timer
sudo systemctl stop session-notify-https-renew.service
sudo bash deploy/https/manage.sh compose stop public-https
```

用户级部署对应使用 `systemctl --user disable --now session-notify-https-renew.timer`、`systemctl --user stop session-notify-https-renew.service`，并去掉 `manage.sh` 前的 `sudo`。

不要运行 `docker compose down`、`down -v`、删除命名卷、重置设备或重生成 `runtime/secrets/server.*`。保留 `runtime/public-https` 中的账户和证书以便恢复；不要提交到 Git、打包分享或输出私钥。恢复可先启动该前门，再 `activate`/`verify`，检查证书仍有效后重新启用 timer。

## 6. 后续更新

后端更新使用仓库内 `deploy/update-server.sh`。已完成本页首次签发和激活后，使用 `bash deploy/update-server.sh --https` 同时更新前门镜像、端口映射和 Nginx 配置，详见[更新说明](../README.zh-CN.md)。已签发 token 的到期时间不会追溯修改。

默认后端更新没有加载 `compose.https.yaml`，即使拉到了本目录的文件，也不会完成首次 HTTPS 签发、激活或定时器安装。首次启用仍需按上文操作。若前门已经部署且 Compose 项目名一致，普通应用更新不带 `down` 或 `--remove-orphans` 时，不会主动删除前门；模板使用 Docker DNS 动态解析后端，允许后端重建后地址变化，切换期间仍可能有短暂失败。

后续修改 HTTPS 部署文件时，可通过 `--https` 应用前两项，也可按需分别操作：

- Nginx 模板变更：执行 `manage.sh activate`，生成运行配置、校验并 reload，再验收。
- 前门镜像或端口映射变更：通过 `manage.sh compose` 拉取所需镜像并重建 `public-https`，随后 `verify`；端口仍从运行配置读取。
- systemd service/timer 变更或仓库搬迁：按第 3 节重新生成并安装所选作用域的 unit，执行对应的 `daemon-reload`，再 `restart session-notify-https-renew.timer` 并运行一次 service；Git 更新不会改写已安装的 unit。

只检查后端 `/health` 不能证明公网证书、入口或续期正常。仓库内更新脚本通过 `--https` 显式处理已配置的前门，并正常校验证书；它不会在应用更新中自动执行首次签发或安装定时器。

实际 IP、端口和 ACME 状态留在被忽略的 `runtime/public-https`；service 路径由生成器填入运行副本，避免修改受 Git 管理的模板而触发更新脚本的“工作区不干净”检查。仓库外的旧更新入口可按[部署总入口](../README.zh-CN.md)迁移为简单转发脚本。

## 版本和验证范围

- 固定官方镜像 `nginx:1.30.5-alpine`、`certbot/certbot:v5.8.0`，不使用 `latest`；上线前按本机架构拉取并记录 digest。部署者后续仍应审查镜像安全更新。
- 可重复执行的检查和验收边界见[部署测试说明](../../tests/deploy/README.md)。部署到新的主机时，需验证 Docker Compose、`nginx -t`、ACME、外网连通性和续期。

官方参考：
- [IP/160 小时证书](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
- [Certbot 5.4+ IP webroot](https://letsencrypt.org/2026/03/11/shorter-certs-certbot.html)
- [Certbot 续期与 deploy hook](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates)
- [Nginx upstream TLS 校验](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_name)
- [systemd 命令参数与变量展开](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)、[配置转义](https://github.com/systemd/systemd/blob/main/man/systemd.syntax.xml)
- [官方 Nginx 镜像](https://hub.docker.com/_/nginx)、[EFF Certbot 镜像版本](https://hub.docker.com/r/certbot/certbot/tags)
