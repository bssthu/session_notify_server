#!/usr/bin/env python3
"""撤销所有已绑设备,回到 bootstrap 态。

用于 strict 配对模式下,本机凭证完全丢失、又没有其他已绑设备能签发配对码的死锁:
在服务端主机本地跑此脚本 → 所有设备撤销 → 首台设备可重新裸 bind。

等价于 localhost 调用 POST /api/v1/devices/reset,但无需服务端在跑、无需 curl。

用法:
    uv run python scripts/reset_devices.py            # 交互确认
    uv run python scripts/reset_devices.py --yes      # 跳过确认
    uv run python scripts/reset_devices.py --db /path/to/session_notify.db
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Windows 控制台默认可能是 GBK,强制 UTF-8 输出避免中文提示乱码。
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# 脚本在 scripts/ 子目录,把项目根加入 sys.path 以便 import app.*
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.storage import Storage  # noqa: E402


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="撤销所有已绑设备,回到 bootstrap 态。")
    parser.add_argument(
        "--db",
        default=os.getenv("SESSION_NOTIFY_DB", "runtime/session_notify.db"),
        help="设备数据库路径(默认:环境变量 SESSION_NOTIFY_DB 或 runtime/session_notify.db)",
    )
    parser.add_argument("--yes", "-y", action="store_true", help="跳过确认提示")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"错误:数据库不存在: {db_path}", file=sys.stderr)
        print("提示:确认服务端 DB 路径,或用 --db 指定。", file=sys.stderr)
        return 1

    storage = Storage(db_path)
    try:
        if not storage.has_any_device():
            print("当前没有已绑设备,已是 bootstrap 态,无需重置。")
            return 0

        if not args.yes:
            answer = input("将撤销所有已绑设备(所有客户端需重新绑定)。继续?[y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("已取消。")
                return 0

        revoked = storage.revoke_all_devices()
        print(f"已撤销 {revoked} 台设备。服务端回到 bootstrap 态。")
        print("下一步:在客户端重新「绑定设备」(首台直接 bind;strict 模式下后续设备走配对码)。")
        return 0
    finally:
        storage.close()


if __name__ == "__main__":
    raise SystemExit(main())
