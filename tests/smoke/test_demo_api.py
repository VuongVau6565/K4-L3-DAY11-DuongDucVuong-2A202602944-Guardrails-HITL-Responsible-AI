import asyncio
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from demo import server


def make_test_runtime(monkeypatch, answer="Model response from test"):
    runtime = server.DemoRuntime()
    monkeypatch.setattr(runtime, "_configuration_error", lambda target: None)
    monkeypatch.setattr(runtime, "_get_agent", lambda target: (object(), object()))
    monkeypatch.setattr(runtime.audit, "export_json", lambda filepath=None: filepath)
    monkeypatch.setattr(runtime.monitor, "export_json", lambda filepath=None: filepath)

    async def fake_chat(agent, runner, message):
        return answer, None

    monkeypatch.setattr(server, "chat_with_agent", fake_chat)
    return runtime


def test_chat_uses_model_response_and_records_observability(monkeypatch):
    runtime = make_test_runtime(monkeypatch, "Live model result")
    result = asyncio.run(runtime.chat(server.ChatRequest(target="red", message="bank account help")))

    assert result["answer"] == "Live model result"
    assert result["target"] == "red"
    assert result["blocked"] is False
    assert runtime.monitor.total_requests == 1
    assert runtime.audit.logs[0]["input"] == "bank account help"


def test_transfer_response_requires_simulated_human_approval(monkeypatch):
    runtime = make_test_runtime(monkeypatch, "Please confirm the transfer request.")
    result = asyncio.run(runtime.chat(server.ChatRequest(
        target="red",
        message="Gửi 100 triệu đến tài khoản demo",
    )))

    assert result["requires_approval"] is True
    assert result["guardrails"]["egress_policy"] == "approval_required"
    assert "không phát sinh giao dịch" in result["answer"]


def test_missing_key_is_reported_without_calling_model(monkeypatch):
    runtime = server.DemoRuntime()
    monkeypatch.setattr(runtime, "_configuration_error", lambda target: "Thiếu OPENROUTER_API_KEY.")

    with pytest.raises(HTTPException) as error:
        asyncio.run(runtime.chat(server.ChatRequest(target="blue", message="Số dư tài khoản")))

    assert error.value.status_code == 503
    assert "OPENROUTER_API_KEY" in error.value.detail
    assert runtime.monitor.total_requests == 0


def test_empty_model_response_is_not_replaced_with_demo_text(monkeypatch):
    runtime = make_test_runtime(monkeypatch, "")
    with pytest.raises(HTTPException) as error:
        asyncio.run(runtime.chat(server.ChatRequest(target="red", message="bank account help")))

    assert error.value.status_code == 502
    assert "phản hồi rỗng" in error.value.detail
    assert runtime.monitor.total_requests == 0
