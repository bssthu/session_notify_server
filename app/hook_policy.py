"""Hook 通知"是否值得创建/保留为可见通知"的策略(服务端版)。

与 PC 客户端 notification-logic.js 的 shouldSuppressClientNotification 对齐:
PostToolUse(用于 resolve 权限请求的传输信号)、idle、paused、无内容 completed 是噪声,
不该作为可见通知创建/保留。needs-confirmation / failure / 有内容的通知一律保留。

创建层过滤(main.receive_hook)与历史堆积清理(storage.acknowledge_legacy_noise_notifications)
共享本判定,确保两处行为一致。
"""
from __future__ import annotations

import re
from typing import Any

# 匹配小写文本(调用方负责 lower)。
_IDLE_HOOK_RE = re.compile(r"\bidle\b|idle_prompt")
_PAUSED_HOOK_RE = re.compile(r"\bpaused\b")
_COMPLETED_HOOK_RE = re.compile(
    r"\btaskcompleted\b|\bcompleted\b|\bcomplete\b|\bdone\b|\bsuccess\b|\bfinished?\b|\bstop\b"
)
_FAILURE_HOOK_RE = re.compile(r"\bstopfailure\b|\bfailure\b|\bfailed\b|\berror\b")


def _nonempty_list(value: object) -> bool:
    return isinstance(value, list) and len(value) > 0


def is_noise_hook_event(
    *,
    event_name: str,
    notification_type: str,
    hook_status: str,
    title: str,
    body_generated: bool,
    raw: dict[str, Any] | None = None,
) -> bool:
    """这组 hook 字段是否属于噪声(不该创建/保留为可见通知)。

    所有文本参数调用前应已 lower;event_name 也应 lower。覆盖 PC 的 4 类 suppress:
    PostToolUse / idle / paused / 无内容 completed。needs-confirmation 与 failure 不命中。
    """
    # 1. PostToolUse:纯传输信号(用于 resolve 权限请求),不弹给用户。
    if event_name == "posttooluse":
        return True

    text = " ".join((event_name, notification_type, hook_status, title))

    # 2. idle 提示。
    if _IDLE_HOOK_RE.search(text):
        return True

    # 3. paused:文本含 paused,或 stop hook 且 raw 含后台任务(codex background_tasks/session_crons)。
    if _PAUSED_HOOK_RE.search(text):
        return True
    if event_name == "stop" and raw:
        if any(
            _nonempty_list(raw.get(key))
            for key in ("background_tasks", "backgroundTasks", "session_crons", "sessionCrons")
        ):
            return True

    # 4. 无内容 completed:body_generated(无真实正文)且非 failure 且命中 completed/stop 类。
    if body_generated and _FAILURE_HOOK_RE.search(text) is None and _COMPLETED_HOOK_RE.search(text):
        return True

    return False
