from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agents.agent import create_red_agent_default, create_blue_agent
from agents.guards_agent import (
    create_red_agent_advance,
    detect_injection_strong,
    topic_filter_strong,
    content_filter_strong,
)
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from assignment.pipeline import build_production_plugins
from core import config
from core.openai_runtime import OpenAIRunner
from core.utils import chat_with_agent
from guardrails.input_guardrails import detect_injection, topic_filter
from guardrails.output_guardrails import content_filter

logger = logging.getLogger("vinbank_demo")
UI = Path(__file__).with_name("index.html")
TRANSFER_PATTERN = r"(chuyển khoản|chuyển tiền|gửi\s*[\d,.]+\s*(triệu|tỷ|đồng|₫)?|transfer money)"


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    target: Literal["blue", "red", "red_advance"]


def _default_guards() -> dict[str, str]:
    return {
        "rate_limit": "not_checked",
        "injection_detection": "not_checked",
        "topic_filter": "not_checked",
        "output_filter": "not_checked",
        "egress_policy": "not_checked",
    }


class DemoRuntime:
    def __init__(self) -> None:
        self.agents: dict[str, tuple[object, object]] = {}
        self.plugins: list[object] = []
        self.audit = AuditLogPlugin()
        self.monitor = MonitoringAlert()
        self.history: list[dict] = []
        self.blue_lock = asyncio.Lock()

    def _configuration_error(self, target: str) -> str | None:
        if target == "blue":
            if not config.get_openrouter_api_key():
                return "Thiếu OPENROUTER_API_KEY. Hãy cấu hình khóa OpenRouter trong file .env ở backend rồi khởi động lại máy chủ."
            return None

        raw_provider = (
            os.environ.get("RED_TEAM_PROVIDER")
            or os.environ.get("LLM_PROVIDER")
            or "openai"
        ).strip().lower()
        if raw_provider not in {"openai", "gemini", "google", "adk"}:
            return "RED_TEAM_PROVIDER không hợp lệ. Chọn openai hoặc gemini trong cấu hình backend."
        provider = config.get_red_provider()
        if provider == config.PROVIDER_GEMINI:
            if not os.environ.get("GOOGLE_API_KEY", "").strip():
                return "Thiếu GOOGLE_API_KEY. Hãy cấu hình khóa Google AI Studio trong file .env ở backend."
            os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "0")
        elif not config.get_openai_api_key():
            return "Thiếu OPENAI_API_KEY. Hãy cấu hình khóa OpenAI trong file .env ở backend."
        return None

    def _get_agent(self, target: str) -> tuple[object, object]:
        if target not in self.agents:
            if target == "blue":
                self.plugins = build_production_plugins(
                    max_requests=5,
                    window_seconds=30,
                    use_llm_judge=False,
                )
                self.agents[target] = create_blue_agent(self.plugins)
            elif target == "red":
                self.agents[target] = create_red_agent_default()
            else:
                self.agents[target] = create_red_agent_advance()
        return self.agents[target]

    async def chat(self, payload: ChatRequest) -> dict:
        target = payload.target
        message = payload.message.strip()
        if not message:
            raise HTTPException(status_code=422, detail="Tin nhắn không được để trống.")

        config_error = self._configuration_error(target)
        if config_error:
            raise HTTPException(status_code=503, detail=config_error)

        request_id = str(uuid.uuid4())
        started = time.perf_counter()
        lock = self.blue_lock if target == "blue" else _AsyncNullLock()
        async with lock:
            try:
                agent, runner = self._get_agent(target)
            except Exception as exc:
                logger.exception("Agent initialization failed: target=%s request_id=%s", target, request_id)
                raise HTTPException(
                    status_code=503,
                    detail="Không khởi tạo được agent. Kiểm tra dependencies, provider và cấu hình model trong backend.",
                ) from exc
            before = self._plugin_counters() if target == "blue" else {}
            try:
                if isinstance(runner, OpenAIRunner):
                    call = asyncio.to_thread(
                        lambda: asyncio.run(chat_with_agent(agent, runner, message))
                    )
                else:
                    call = chat_with_agent(agent, runner, message)
                answer, _ = await asyncio.wait_for(call, timeout=90)
            except asyncio.TimeoutError as exc:
                logger.exception("Model request timed out: target=%s request_id=%s", target, request_id)
                raise HTTPException(
                    status_code=504,
                    detail="Model không phản hồi trong 90 giây. Hãy thử lại hoặc kiểm tra trạng thái nhà cung cấp.",
                ) from exc
            except Exception as exc:
                logger.exception("Model request failed: target=%s request_id=%s", target, request_id)
                raise HTTPException(
                    status_code=502,
                    detail="Không gọi được model. Hãy kiểm tra API key, provider/model trong .env và nhật ký backend.",
                ) from exc

            if not isinstance(answer, str) or not answer.strip():
                raise HTTPException(
                    status_code=502,
                    detail="Model trả về phản hồi rỗng. Không có câu trả lời dự phòng được tạo.",
                )
            answer = answer.strip()
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            result = self._format_result(
                target=target,
                message=message,
                answer=answer,
                latency_ms=latency_ms,
                before=before,
            )
            self._record(request_id, target, message, result)
            return result

    def _plugin_counters(self) -> dict[str, int]:
        if not self.plugins:
            return {}
        limiter, input_guard, output_guard = self.plugins
        return {
            "rate_total": limiter.total_count,
            "rate_blocked": limiter.blocked_count,
            "input_total": input_guard.total_count,
            "input_blocked": input_guard.blocked_count,
            "output_total": output_guard.total_count,
            "output_redacted": output_guard.redacted_count,
        }

    def _format_result(
        self,
        *,
        target: str,
        message: str,
        answer: str,
        latency_ms: float,
        before: dict[str, int],
    ) -> dict:
        blocked = False
        layer = "LLM"
        guards = _default_guards()
        requires_approval = bool(
            re.search(TRANSFER_PATTERN, message, re.IGNORECASE)
        )
        redacted = False

        if target == "blue":
            after = self._plugin_counters()
            rate_blocked = after["rate_blocked"] > before.get("rate_blocked", 0)
            input_blocked = after["input_blocked"] > before.get("input_blocked", 0)
            redacted = after["output_redacted"] > before.get("output_redacted", 0)
            guards["rate_limit"] = "block" if rate_blocked else "allow"
            guards["injection_detection"] = (
                "block" if input_blocked and detect_injection(message) == "BLOCK" else
                "allow" if not input_blocked else "not_checked"
            )
            guards["topic_filter"] = (
                "block" if input_blocked and topic_filter(message) == "BLOCK" else
                "allow" if not input_blocked else "not_checked"
            )
            guards["output_filter"] = "redact" if redacted else (
                "not_checked" if rate_blocked or input_blocked else "allow"
            )
            guards["egress_policy"] = "approval_required" if requires_approval else "not_applicable"
            if rate_blocked:
                blocked, layer = True, "Rate Limit"
            elif input_blocked:
                blocked = True
                layer = "Injection Detection" if detect_injection(message) == "BLOCK" else "Topic Filter"
            elif redacted:
                layer = "Output PII/Secret Filter"
            elif requires_approval:
                layer = "Human-in-the-Loop"
        elif target == "red_advance":
            injection_blocked = detect_injection_strong(message)
            topic_blocked = topic_filter_strong(message)
            guards["rate_limit"] = "not_applicable"
            guards["injection_detection"] = "block" if injection_blocked else "allow"
            guards["topic_filter"] = "block" if topic_blocked else "allow"
            output_check = content_filter_strong(answer)
            guards["output_filter"] = "redact" if output_check["issues"] else "allow"
            guards["egress_policy"] = "approval_required" if requires_approval else "not_applicable"
            blocked = injection_blocked or topic_blocked
            if injection_blocked:
                layer = "Injection Detection"
            elif topic_blocked:
                layer = "Topic Filter"
            elif output_check["issues"]:
                layer = "Output Secret Filter"
            elif requires_approval:
                layer = "Human-in-the-Loop"
        else:
            guards = {key: "not_applicable" for key in guards}
            guards["egress_policy"] = "approval_required" if requires_approval else "not_applicable"
            if requires_approval:
                layer = "Human-in-the-Loop"

        if requires_approval and not blocked:
            answer = (
                f"{answer}\n\n"
                "Human-in-the-Loop: yêu cầu đang chờ người duyệt. "
                "Đây là mô phỏng — không phát sinh giao dịch."
            )

        return {
            "request_id": "",
            "target": target,
            "answer": answer,
            "blocked": blocked,
            "layer": layer,
            "guardrails": guards,
            "latency_ms": latency_ms,
            "requires_approval": requires_approval,
            "status": "block" if blocked else "pending" if requires_approval else "redact" if redacted else "allow",
            "provider": config.blue_provider_label() if target == "blue" else config.red_provider_label(),
        }

    def _record(self, request_id: str, target: str, message: str, result: dict) -> None:
        result["request_id"] = request_id
        self.audit.record_input(user_id="demo", text=message, request_id=request_id)
        self.audit.record_output(
            user_id="demo",
            text=result["answer"],
            blocked=result["blocked"],
            layer=f"{target}:{result['layer']}",
            request_id=request_id,
        )
        self.monitor.total_requests += 1
        if result["blocked"]:
            self.monitor.blocked_requests += 1
        if result["guardrails"]["rate_limit"] == "block":
            self.monitor.rate_limit_hits += 1
        try:
            self.monitor.export_json(str(ROOT / "outputs" / "ui_metrics.json"))
            self.audit.export_json(str(ROOT / "outputs" / "ui_audit_log.json"))
        except OSError as exc:
            logger.exception("Audit or metrics export failed: request_id=%s", request_id)
            raise HTTPException(
                status_code=500,
                detail="Model đã phản hồi nhưng không ghi được audit/metrics. Kiểm tra quyền ghi thư mục outputs.",
            ) from exc
        self.history.insert(0, {
            "id": request_id,
            "time": self.audit.logs[-1]["timestamp"],
            "request": message,
            "target": target,
            "status": result["status"],
            "blocked": result["blocked"],
            "layer": result["layer"],
            "duration": result["latency_ms"],
            "answer": result["answer"],
            "detail": self._detail(result),
        })

    @staticmethod
    def _detail(result: dict) -> str:
        states = ", ".join(f"{key}: {value}" for key, value in result["guardrails"].items())
        if result["blocked"]:
            return f"Yêu cầu bị chặn tại {result['layer']}. Trạng thái lớp: {states}."
        if result["requires_approval"]:
            return f"Yêu cầu chuyển khoản chỉ được mô phỏng và đang chờ người duyệt. Không phát sinh giao dịch. {states}."
        return f"Đã nhận phản hồi từ model {result['provider']}. Trạng thái lớp: {states}."

    def state(self) -> dict:
        snapshot = self.monitor.snapshot()
        return {
            "metrics": {
                "total": snapshot["total_requests"],
                "blocked": snapshot["blocked_requests"],
                "limited": snapshot["rate_limit_hits"],
                "protected": sum(
                    1 for row in self.history if row["status"] == "redact"
                ),
            },
            "audit": self.history[:100],
            "configuration": {
                "blue_ready": self._configuration_error("blue") is None,
                "red_ready": self._configuration_error("red") is None,
                "red_advance_ready": self._configuration_error("red_advance") is None,
            },
        }


class _AsyncNullLock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


runtime = DemoRuntime()


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="VinBank AI Safety Lab",
    description="Local demo API for Blue, Red, and Red Advance agents.",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(UI)


@app.get("/app.js", include_in_schema=False)
async def frontend_script():
    return FileResponse(UI.with_name("app.js"), media_type="text/javascript")


@app.get("/api/state")
async def get_state():
    return runtime.state()


@app.post("/api/chat")
async def chat(payload: ChatRequest):
    return await runtime.chat(payload)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("demo.server:app", host="127.0.0.1", port=8000, reload=False)
