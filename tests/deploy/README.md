# 部署工具验证

本目录只包含测试及测试依赖，不参与应用镜像和实际续期。测试仅复制显式允许的公开脚本/模板，不读取真实 `runtime`、数据库、私钥或 ACME 账户。

## 跨平台单元测试

从仓库根目录运行，使用项目的 Python 3.11+ 开发环境：

```sh
uv run pytest tests/deploy
```

这些测试也包含在默认 `uv run pytest` 中，覆盖复制隔离、systemd 模板渲染、路径特殊字符及非法控制字符。不需要 Docker、systemd 服务管理器或公网证书。

## Linux 离线流程测试

需要 Python 3、Bash、OpenSSL（支持 `req -addext`）、`timeout`、`flock`，HTTPS 测试额外需要 PyYAML。与应用运行依赖隔离；可使用 Linux 或 WSL 的独立虚拟环境：

```sh
python3 -m venv runtime/deploy-test-venv
runtime/deploy-test-venv/bin/python -m pip install -r tests/deploy/requirements.txt
runtime/deploy-test-venv/bin/python tests/deploy/run_https_offline.py
runtime/deploy-test-venv/bin/python tests/deploy/run_update_offline.py
bash -n deploy/update-server.sh
bash -n deploy/https/manage.sh
bash -n deploy/update-server-wrapper.sh.in
```

依赖安装需要网络；测试本身不联网、不接触 Docker daemon、不执行真实 Git 拉取或重建，不安装或启用 systemd unit。`run_*.py` 是独立 Linux 入口，不在默认 pytest 收集范围，避免 Windows 测试触发 Linux 工具。

- HTTPS 流程模拟 Docker、Nginx、curl、ss 和 TLS 网络握手，用真实 OpenSSL 验证证书 DNS SAN、信任链及 IP 身份。覆盖默认/自定义端口、无邮箱配置、首次签发前置条件、staging 隔离、错误证书拒绝、reload 失败恢复、续期重试和无变化不 reload。
- 更新流程模拟 Git、Docker、curl 和 HTTPS 管理入口，在带空格的临时仓库中运行真实 Bash 更新脚本。覆盖 fast-forward 后重新进入脚本、自定义项目和健康地址、仅后端/包含 HTTPS、干净工作区、失败中止和不自动签发/安装定时器。
- systemd 渲染测试只生成临时文件，不等于服务管理器实际加载成功。

需要完整应用回归时使用 `uv run pytest`；这是独立于上述 Linux 流程测试的一组检查。

## 目标环境验收

上线时另行记录实际命令、版本和结果；不要将某一次本机测试记录当作所有主机都已验证。至少确认：

1. 合并后的 Compose 使用原项目、数据库卷和证书，只新增预期端口；自定义 HTTPS 端口与运行配置一致。
2. `nginx -t`、首次签发、激活和正常校验证书的外部 `/health` 检查成功。
3. 生成的 unit 经目标机 `systemd-analyze verify` 校验；所选系统/用户定时器启用，用户级方案配置 linger，手动运行一次续期服务成功。
4. 使用 ACME staging/dry-run 演练续期，未将 staging 证书装载到生产；确认续期失败和证书即将到期有监控。
5. 独立客户端配对、Bearer 调用、刷新及凭据保存成功，旧 token 被拒绝。
6. 应用重建后原客户端和公网入口都恢复可用；数据库与设备凭据保留。

操作命令见[部署入口](../../deploy/README.zh-CN.md)和[HTTPS 指南](../../deploy/https/README.zh-CN.md)。
