# Linux 部署与更新

本目录提供服务端的可选部署工具，随源码一起维护。`https/` 是需要公有 CA 信任时使用的独立入口；应用进程不负责证书签发或定时续期。所有命令默认从服务端仓库根目录执行，不依赖仓库的目录名、服务器用户名或公网 IP。

## 配置边界

| 内容 | 位置 | Git 管理 |
| --- | --- | --- |
| 通用脚本、配置样例、systemd 模板 | `deploy/` | 是 |
| 基础服务及可选 HTTPS 服务定义 | `compose.yaml`、`compose.https.yaml` | 是 |
| 本机更新参数 | `runtime/deploy/update.env` | 否 |
| Compose 后端端口与项目插值参数 | 根目录 `.env` | 否 |
| HTTPS 参数、证书、ACME 账户、生成配置 | `runtime/public-https/` | 否 |
| 已有后端证书及私钥 | `runtime/secrets/` | 否 |
| 安装后的定时器 | 系统或用户 systemd 目录 | 否 |
| 部署测试和测试依赖 | `tests/deploy/` | 是 |

机器参数只填写在样例的运行副本中，不修改仓库里的样例。运行目录包含凭据，需要限制权限并纳入自己的备份方案；Git 和 Docker 构建上下文都排除它。`compose.override.yaml` 也被忽略，可用于基础 Compose 的本机覆盖。HTTPS 管理脚本显式合并两个仓库 Compose 文件；它不会自动加载此 override，若自定义网络、卷或后端端口，须先审查与 HTTPS 入口的兼容性。

供操作者或 agent 接手时，先确认：是否首次部署、现有 Compose 项目名、数据卷、原证书、部署用户的 Docker 权限，以及实际入口地址和端口。已有部署不得重新生成原证书、初始化数据库或更换项目名。

## 首次部署后端

需要 Git、Docker Engine、Compose v2、Bash、OpenSSL、curl、flock 和 Python 3。将服务端仓库克隆到自行选择的目录，进入仓库；以下证书生成命令**仅用于首次部署且证书不存在时**：

```sh
bash scripts/generate_self_signed_cert.sh
docker compose config --quiet
docker compose up -d --build server
curl --fail --show-error --cacert runtime/secrets/server.crt https://127.0.0.1:8765/health
docker compose exec server python scripts/issue_bootstrap_code.py
```

基础 Compose 默认发布 8765，数据库使用命名卷；首次配对和客户端指纹固定见[主 README](../README.md)。后续签发配对码和数据管理应使用容器内同一个数据库。

需要公有 CA 信任的客户端，再按[公网 HTTPS 部署说明](https/README.zh-CN.md)启用额外入口。该方案针对固定公网 IPv4、Linux Docker 和 HTTP-01 验证；需要公网 80 端口，HTTPS 对外端口可配置。附带 HTTPS 工具从 Compose 读取后端端口，原证书仍读取 `runtime/secrets/server.crt`；自定义证书路径的部署须先审查适配。已有统一反向代理的环境可使用自己的证书管理方式，无需启用这里的 Nginx/Certbot 组件。

## 配置后端端口

在仓库根目录被忽略的 `.env` 中设置，已有文件应编辑并保留其他配置：

```sh
SESSION_NOTIFY_PORT=9876
SESSION_NOTIFY_HOST_PORT=19876
```

本例容器内 uvicorn 监听 `9876`，宿主机发布 `19876`；省略 `SESSION_NOTIFY_HOST_PORT` 时跟随容器端口，两者均省略时继续使用 `8765`。HTTPS 预检连接 `127.0.0.1:19876`，Nginx 访问 `server:9876`，更新脚本的默认健康检查自动使用宿主机端口。端口须为 1–65535 内的整数，并保持一个 IPv4 回环可访问的 TCP 发布端口。`HTTPS_PUBLIC_PORT` 独立配置公网入口，不会改变后端端口。

修改前保留原 `.env`，确认防火墙及客户端地址同步调整；端口更改须重建后端容器，不能仅 reload Nginx。先检查 `docker compose config --quiet`，再按下节更新；已有公网 HTTPS 入口时使用 `--https` 同时重新生成 Nginx 上游配置。此前若在 `runtime/deploy/update.env` 显式固定了 `UPDATE_HEALTH_URL`，应同步修改，或置空以启用自动读取。

## 更新现有部署

仓库工作区必须干净，默认从当前分支的 upstream 执行 `git pull --ff-only`。本地提交须先由维护者推送，服务器才能拉取。使用有权访问原部署配置和 Docker 的同一个用户运行：

```sh
bash deploy/update-server.sh
```

脚本检查已有 `server` 容器和 Compose 配置，拉取代码后重新进入新版脚本，执行 `docker compose up -d --build server`，并使用原证书校验后端 `/health`。不会清空数据库、重置设备、删除其他容器或修改定时器；重建应用会有短暂中断。失败返回非零，不自动执行代码或数据库回滚。

默认健康检查是 `https://127.0.0.1:<Compose 后端发布端口>/health`（默认端口 8765），使用 `runtime/secrets/server.crt` 信任后端。自定义健康检查地址、证书或项目名时，复制配置后填写：

```sh
install -d -m 700 runtime/deploy
install -m 600 deploy/update.env.example runtime/deploy/update.env
# 用编辑器修改 runtime/deploy/update.env
```

`UPDATE_COMPOSE_PROJECT` 留空时沿用 Compose 默认选择（包括现有 `.env`/环境变量）；填写时必须与原容器的项目标签一致。`UPDATE_HEALTH_URL` 留空时读取 Compose 端口，也支持显式覆盖；证书必须与该 URL 身份匹配。显式健康地址只改变健康检查，不改变容器监听、端口映射或 Nginx 上游。更新脚本不使用 `--insecure`；校验失败时排查地址、信任证书及到期时间。

公网 HTTPS **已经完成签发和激活**时，可将前门一起更新：

```sh
bash deploy/update-server.sh --https
```

此选项先确认两套配置指向同一个已有后端和前门，再拉取 HTTPS 镜像、更新后端、重建前门以应用镜像/端口变化，并重新生成 Nginx 配置、校验和 reload。公网端口来自 `runtime/public-https/config.env`。它不会执行首次签发、接受 CA 条款或安装定时器。还需从外部网络检查实际 HTTPS 地址。

不传 `--https` 只更新应用；已部署的前门和续期定时器继续独立运行。service/timer 模板改变后，应按 HTTPS 文档重新生成、安装并重新加载，Git 更新不会修改已安装的 unit。

已手动拉取并审阅代码，或有意使用 detached HEAD 时：

```sh
bash deploy/update-server.sh --no-pull
# 已启用公网 HTTPS 时：
bash deploy/update-server.sh --no-pull --https
```

`--no-pull` 只跳过 Git 拉取；应用镜像构建仍可能下载基础镜像及 Python 依赖，`--https` 还会显式拉取 Nginx/Certbot 镜像。它不保证完全离线更新；隔离网络部署需预先准备所需镜像和构建依赖。

失败后根据退出信息检查 `docker compose ps server` 和本机日志。回滚前确认旧代码与现有数据库兼容并保留备份；切到经过审核的旧版本后使用 `--no-pull` 重建。如果旧版本没有此脚本，使用该版本的 Compose 部署说明。不要使用 `down -v` 或重新生成证书来解决更新失败。

## 接管仓库外的旧更新入口

如果服务器原来在仓库父目录放了 `update-server.sh` 和 `UPDATE.md`，这两个文件不会被本仓库的 `git pull` 更新。迁移在目标服务器另行执行：

1. 核对旧脚本的项目名、健康检查地址及本机定制，将需要保留的参数写入 `runtime/deploy/update.env`。
2. 在干净仓库中执行新版脚本并确认后端健康；已有 HTTPS 入口时再验证 `--https`。
3. 备份旧入口，用 `deploy/update-server-wrapper.sh.in` 的副本替换，**仅在副本中**填写仓库绝对路径，并保留入口的可执行权限。它将参数原样传给仓库内脚本，不复制更新逻辑。
4. 将旧 `UPDATE.md` 改成指向本仓库 `deploy/README.zh-CN.md` 的简短说明，保留机器专属信息在服务器本地。

迁移前旧入口仍可按原方式更新后端；它不会因为拉取到 HTTPS 文件而自动启用入口或修改续期设置。

## 验证

可重复执行的本地检查、依赖和真实部署验收见[部署测试说明](../tests/deploy/README.md)。离线测试与实际签发/上线验收应分别记录；测试通过不代表公网网关已接通。
