from __future__ import annotations

import hashlib
from itertools import permutations
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import utc_now


def digest(title):
    return hashlib.sha256(title.encode()).hexdigest()


def ask(titles=("Question?",), *, call="call-1", session="session-1", at=None):
    return {
        "hook_event_name": "PreToolUse", "event_type": "approval_requested",
        "tool_name": "functions.request_user_input_async", "session_id": session, "turn_id": "turn-1",
        "prompt": titles[0], "metadata": {"delivery_id": uuid4().hex},
        "codex_async": {"kind": "asked", "observed_at": (at or utc_now()).isoformat(),
                        "call_id": call, "question_hashes": [digest(title) for title in titles]},
    }


def answer(title="Question?", *, session="session-1", at=None):
    return {
        "hook_event_name": "UserPromptSubmit", "session_id": session, "turn_id": "later-turn",
        "metadata": {"delivery_id": uuid4().hex},
        "codex_async": {"kind": "answered", "observed_at": (at or utc_now()).isoformat(),
                        "question_hash": digest(title)},
    }


def bind(client, name="test"):
    response = client.post("/api/v1/devices/bind", json={"name": name, "platform": "windows"})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def post(client, payload, headers, source="codex"):
    response = client.post("/api/v1/hooks/" + source, json=payload, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def active(client, headers):
    return client.get("/api/v1/notifications", headers=headers).json()


def ack_events(client, headers):
    return [event for event in client.get("/api/v1/events", headers=headers).json()["events"]
            if event["event_type"] == "notification.acknowledged"]


def test_multiple_answers_cross_turn_persist_and_broadcast(tmp_path):
    db = tmp_path / "server.db"
    with TestClient(create_app(db)) as client:
        headers = bind(client)
        question = ask(("First?", "Second?"))
        created = post(client, question, headers)
        post(client, {**question, "hook_event_name": "PostToolUse", "codex_async": None,
                      "tool_response": {"accepted": True}}, headers)
        assert len(active(client, headers)) == 1
        post(client, {"hook_event_name": "Stop", "session_id": "session-1"}, headers)
        assert len(active(client, headers)) == 1
        first_answer = answer("First?")
        assert post(client, first_answer, headers) is None
        post(client, first_answer, headers)
        post(client, answer("First?"), headers)
        assert len(active(client, headers)) == 1
        assert not ack_events(client, headers)
    with TestClient(create_app(db)) as client:
        assert len(active(client, headers)) == 1
        post(client, answer("Second?"), headers)
        assert active(client, headers) == []
        events = ack_events(client, headers)
        assert len(events) == 1
        assert events[0]["notification_id"] == created["id"]
        assert events[0]["reason"] == "async_question_answered"
        assert post(client, question, headers)["status"] == "acknowledged"
        assert len(ack_events(client, headers)) == 1
    with TestClient(create_app(db)) as client:
        assert active(client, headers) == []


def test_answer_delivered_before_question_is_reconciled_after_restart(tmp_path):
    db = tmp_path / "server.db"
    question = ask(at=utc_now() - timedelta(seconds=10))
    with TestClient(create_app(db)) as client:
        headers = bind(client)
        post(client, answer(), headers)
        assert active(client, headers) == []
    with TestClient(create_app(db)) as client:
        created = post(client, question, headers)
        assert created["status"] == "acknowledged"
        assert active(client, headers) == []
        assert len(ack_events(client, headers)) == 1


@pytest.mark.parametrize("mode", ["different_session", "different_device", "different_source", "partial", "future_question"])
def test_unrelated_answer_does_not_clear(tmp_path, mode):
    with TestClient(create_app(tmp_path / "server.db")) as client:
        headers = bind(client)
        other_headers = bind(client, "other")
        question = ask(at=utc_now() + timedelta(seconds=30) if mode == "future_question" else None)
        created = post(client, question, headers)
        response = answer("Question" if mode == "partial" else "Question?",
                          session="other-session" if mode == "different_session" else "session-1")
        post(client, response, other_headers if mode == "different_device" else headers,
             "claude" if mode == "different_source" else "codex")
        assert created["id"] in [item["id"] for item in active(client, headers)]
        assert not ack_events(client, headers)


@pytest.mark.parametrize("mode", ["two_calls", "same_call", "already_answered"])
def test_repeated_question_titles_are_ambiguous(tmp_path, mode):
    with TestClient(create_app(tmp_path / "server.db")) as client:
        headers = bind(client)
        post(client, ask(("Question?", "Question?") if mode == "same_call" else ("Question?",)), headers)
        if mode == "already_answered":
            post(client, answer(), headers)
            assert active(client, headers) == []
        if mode != "same_call":
            post(client, ask(call="call-2"), headers)
        expected = len(active(client, headers))
        post(client, answer(), headers)
        assert len(active(client, headers)) == expected


@pytest.mark.parametrize("event", ["Stop", "TaskCompleted", "StopFailure", "SubagentStop"])
def test_finalize_preserves_async_but_clears_ordinary_approval(tmp_path, event):
    with TestClient(create_app(tmp_path / "server.db")) as client:
        headers = bind(client)
        created = post(client, ask(), headers)
        legacy = post(client, {"hook_event_name": "PreToolUse", "event_type": "approval_requested",
                               "tool_name": "request_user_input_async", "session_id": "session-1",
                               "prompt": "Legacy question?"}, headers)
        ordinary = post(client, {"hook_event_name": "PermissionRequest", "session_id": "session-1",
                                 "tool_name": "shell_command", "prompt": "Permission?"}, headers)
        post(client, {"hook_event_name": event, "session_id": "session-1"}, headers)
        ids = [item["id"] for item in active(client, headers)]
        assert created["id"] in ids and legacy["id"] in ids
        assert ordinary["id"] not in ids


def test_full_hashes_disambiguate_same_preview_and_manual_ack_is_idempotent(tmp_path):
    with TestClient(create_app(tmp_path / "server.db")) as client:
        headers = bind(client)
        titles = ["x" * 220 + name + "z" * 80 for name in ("A", "B")]
        first = post(client, ask((titles[0],), call="a"), headers)
        second = post(client, ask((titles[1],), call="b"), headers)
        post(client, answer(titles[1]), headers)
        assert [item["id"] for item in active(client, headers)] == [first["id"]]
        assert ack_events(client, headers)[0]["notification_id"] == second["id"]
        client.post(f"/api/v1/notifications/{first['id']}/ack", headers=headers, json={"reason": "user_confirmed"})
        before = len(ack_events(client, headers))
        post(client, answer(titles[0]), headers)
        assert len(ack_events(client, headers)) == before


def test_ordinary_prompt_is_transport_only_even_without_new_metadata(tmp_path):
    with TestClient(create_app(tmp_path / "server.db")) as client:
        headers = bind(client)
        assert post(client, {"hook_event_name": "UserPromptSubmit", "prompt": "Continue", "session_id": "session-1"}, headers) is None
        assert active(client, headers) == []


@pytest.mark.parametrize("order", list(permutations(("first", "second", "answer"))))
def test_ambiguous_answers_converge_for_every_delivery_order_across_restarts(tmp_path, order):
    db = tmp_path / "server.db"
    now = utc_now() - timedelta(seconds=10)
    payloads = {
        "first": ask(call="call-1", at=now),
        "second": ask(call="call-2", at=now + timedelta(seconds=1)),
        "answer": answer(at=now + timedelta(seconds=2)),
    }
    with TestClient(create_app(db)) as client:
        headers = bind(client)
    for kind in order:
        with TestClient(create_app(db)) as client:
            post(client, payloads[kind], headers)
    with TestClient(create_app(db)) as client:
        pending = active(client, headers)
        assert {item["metadata"]["codex_async"]["call_id"] for item in pending} == {"call-1", "call-2"}
        events_before_replay = client.get("/api/v1/events", headers=headers).json()["events"]
        # The existing event contract must restore the same ids on live clients.
        visible = set()
        for event in events_before_replay:
            if event["event_type"] == "notification.created":
                visible.add(event["notification"]["id"])
            elif event["event_type"] == "notification.acknowledged":
                visible.discard(event["notification_id"])
        assert visible == {item["id"] for item in pending}
        for payload in payloads.values():
            post(client, payload, headers)
        assert client.get("/api/v1/events", headers=headers).json()["events"] == events_before_replay


@pytest.mark.parametrize("manual_timing", ["before_answer", "after_answer"])
@pytest.mark.parametrize("other_device", [False, True])
def test_late_ambiguity_never_undoes_manual_ack(tmp_path, manual_timing, other_device):
    with TestClient(create_app(tmp_path / "server.db")) as client:
        headers = bind(client)
        manual_headers = bind(client, "other") if other_device else headers
        now = utc_now() - timedelta(seconds=10)
        first = post(client, ask(at=now), headers)
        def manual_ack():
            response = client.post(f"/api/v1/notifications/{first['id']}/ack",
                                   headers=manual_headers, json={"reason": "user_confirmed"})
            assert response.status_code == 200
        if manual_timing == "before_answer":
            manual_ack()
        post(client, answer(at=now + timedelta(seconds=2)), headers)
        if manual_timing == "after_answer":
            manual_ack()
        second = post(client, ask(call="call-2", at=now + timedelta(seconds=1)), headers)
        assert [item["id"] for item in active(client, headers)] == [second["id"]]


def test_late_ambiguity_does_not_restore_expired_question(tmp_path):
    app = create_app(tmp_path / "server.db")
    with TestClient(app) as client:
        headers = bind(client)
        now = utc_now() - timedelta(seconds=10)
        first = post(client, ask(at=now), headers)
        post(client, answer(at=now + timedelta(seconds=2)), headers)
        with app.state.storage._conn:
            app.state.storage._conn.execute(
                "UPDATE notifications SET expires_at = ? WHERE id = ?", (now.isoformat(), first["id"]),
            )
        second = post(client, ask(call="call-2", at=now + timedelta(seconds=1)), headers)
        assert [item["id"] for item in active(client, headers)] == [second["id"]]


def test_retracted_auto_ack_is_pushed_as_active_notification(tmp_path):
    with TestClient(create_app(tmp_path / "server.db")) as client:
        headers = bind(client)
        now = utc_now() - timedelta(seconds=10)
        with client.websocket_connect("/api/v1/ws", headers=headers) as websocket:
            first = post(client, ask(at=now), headers)
            assert websocket.receive_json()["notification"]["id"] == first["id"]
            post(client, answer(at=now + timedelta(seconds=2)), headers)
            assert websocket.receive_json()["event_type"] == "notification.acknowledged"
            second = post(client, ask(call="call-2", at=now + timedelta(seconds=1)), headers)
            assert websocket.receive_json()["notification"]["id"] == second["id"]
            restored = websocket.receive_json()
            assert restored["event_type"] == "notification.created"
            assert restored["reason"] == "async_question_ambiguous"
            assert restored["notification"]["id"] == first["id"]
            assert restored["notification"]["status"] == "active"
            assert restored["notification"]["expires_at"] == first["expires_at"]
