"""pytest 公共夹具。

配对码门禁(SESSION_NOTIFY_PAIR_MODE)默认 strict:已有已绑设备后裸 bind 被拒。存量测试
大多会多次裸 bind 绑多台设备来验证绑定之后的逻辑(origin device / refresh / device
management),与门禁无关。这里把测试环境默认设为 easy,让多 bind 正常;配对码门禁在
专项测试(test_pair_*)里单独 monkeypatch 切回 strict 验证。
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _easy_pair_mode_by_default(monkeypatch):
    monkeypatch.setenv("SESSION_NOTIFY_PAIR_MODE", "easy")
