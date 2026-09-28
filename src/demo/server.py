"""Local API and static UI for live Blue / Red / Red Advance demonstrations.

Run from the repository root with:
    python -m uvicorn --app-dir src demo.server:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from agents.agent import create_blue_agent, create_red_agent_default
from agents.guards_agent import (
    check_secret_leak,
    create_red_agent_advance,
    detect_injection_strong,
    topic_filter_strong,
)
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from assignment.pipeline import build_production_plugins
from core.config import (
    BLUE_MODEL,
    get_openai_api_key,
    get_openrouter_api_key,
    get_red_model,
    get_red_provider,
    red_uses_gemini,
)

ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).resolve().parent / "static"


class ChatRequest(BaseModel):
    target: str = Field(pattern=r"^(blue|red|red_advance)$")
    message: str = Field(min_length=1, max_length=5000)
    user_id: str = Field(default="demo-user", min_length=1, max_length=80)


class ApprovalRequest(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    amount: str = Field(default="100000000 VND", max_length=80)


class DemoRuntime:
    def __init__(self):
        self.blue_plugins = build_production_plugins(use_llm_judge=False)
        self.blue_agent, self.blue_runner = create_blue_agent(self.blue_plugins)
        self.red_agent, self.red_runner = create_red_agent_default()
        self.advance_agent, self.advance_runner = create_red_agent_advance()
        self.audit = AuditLogPlugin()
        self.monitor = MonitoringAlert()
        self.locks = {key: asyncio.Lock() for key in ("blue", "red", "red_advance")}
        self.sessions: dict[str, str] = {}

    def pair(self, target: str):
        return {
            "blue": (self.blue_agent, self.blue_runner),
            "red": (self.red_agent, self.red_runner),
            "red_advance": (self.advance_agent, self.advance_runner),
        }[target]


runtime: DemoRuntime | None = None
app = FastAPI(title="VinBank AI Safety Lab", docs_url=None, redoc_url=None)


def _ensure_runtime() -> DemoRuntime:
    global runtime
    if runtime is None:
        runtime = DemoRuntime()
    return runtime


def _blue_plugins(rt: DemoRuntime) -> dict[str, object]:
    return {plugin.name: plugin for plugin in rt.blue_plugins}


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/config")
async def config():
    provider = get_red_provider()
    if red_uses_gemini():
        import os
        red_key_configured = bool(os.environ.get("GOOGLE_API_KEY", "").strip())
    else:
        red_key_configured = bool(get_openai_api_key())
    return {
        "blue_model": BLUE_MODEL,
        "blue_key_configured": bool(get_openrouter_api_key()),
        "red_provider": provider,
        "red_model": get_red_model(),
        "red_key_configured": red_key_configured,
        "audit_file": "outputs/demo_audit_log.json",
    }


@app.post("/api/chat")
async def chat(request: ChatRequest):
    rt = _ensure_runtime()
    target = request.target
    agent, runner = rt.pair(target)
    request_id = str(uuid.uuid4())
    started = time.perf_counter()
    key = f"{request.user_id}:{target}"

    async with rt.locks[target]:
        blue = _blue_plugins(rt) if target == "blue" else {}
        before = {
            name: {
                "blocked": getattr(plugin, "blocked_count", 0),
                "redacted": getattr(plugin, "redacted_count", 0),
            }
            for name, plugin in blue.items()
        }
        rt.audit.record_input(user_id=request.user_id, text=request.message, request_id=request_id)
        try:
            from core.utils import chat_with_agent

            response, session = await chat_with_agent(
                agent,
                runner,
                request.message,
                session_id=rt.sessions.get(key),
                user_id=request.user_id,
            )
            if session is not None:
                rt.sessions[key] = session.id
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
            rt.audit.record_output(
                user_id=request.user_id,
                text=f"LLM request failed ({type(exc).__name__})",
                blocked=False,
                layer="model_error",
                request_id=request_id,
            )
            rt.monitor.total_requests += 1
            rt.audit.export_json(str(ROOT / "outputs" / "demo_audit_log.json"))
            rt.monitor.export_json(str(ROOT / "outputs" / "demo_metrics.json"))
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "Không gọi được model. Kiểm tra API key, model và kết nối rồi thử lại.",
                    "provider_status": str(code) if code is not None else None,
                    "error_type": type(exc).__name__,
                    "latency_ms": elapsed_ms,
                },
            ) from None

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        blocked = False
        redacted = False
        layer = None
        guardrails = []

        if target == "blue":
            rate = blue["rate_limiter"]
            input_guard = blue["input_guardrail"]
            output_guard = blue["output_guardrail"]
            if rate.blocked_count > before.get("rate_limiter", {}).get("blocked", 0):
                blocked, layer = True, "rate_limiter"
            elif input_guard.blocked_count > before.get("input_guardrail", {}).get("blocked", 0):
                blocked, layer = True, "input_guardrail"
            if output_guard.redacted_count > before.get("output_guardrail", {}).get("redacted", 0):
                redacted, layer = True, "output_guardrail"
            rate_status = "blocked" if layer == "rate_limiter" else "skipped" if blocked else "passed"
            input_status = "blocked" if layer == "input_guardrail" else "skipped" if layer == "rate_limiter" else "passed"
            guardrails = [
                {"name": "Rate Limiter", "status": rate_status},
                {"name": "Input Guardrails", "status": input_status},
                {"name": "Output Guardrails", "status": "redacted" if redacted else "skipped" if blocked else "passed"},
            ]
        elif target == "red_advance":
            if detect_injection_strong(request.message):
                blocked, layer = True, "input_injection"
            elif topic_filter_strong(request.message):
                blocked, layer = True, "input_topic"
            elif "cannot share internal system details" in response.lower():
                redacted, layer = True, "output_guardrail"
            guardrails = [
                {"name": "Red Advance input", "status": "blocked" if blocked else "passed"},
                {"name": "Red Advance output", "status": "redacted" if redacted else "skipped" if blocked else "passed"},
            ]
        else:
            guardrails = [{"name": "Red guardrails", "status": "disabled by design"}]

        leaked = check_secret_leak(response) if target in {"red", "red_advance"} else False
        rt.monitor.total_requests += 1
        if blocked:
            rt.monitor.blocked_requests += 1
        if layer == "rate_limiter":
            rt.monitor.rate_limit_hits += 1
        rt.audit.record_output(
            user_id=request.user_id,
            text=response,
            blocked=blocked,
            layer=layer,
            request_id=request_id,
        )
        rt.audit.export_json(str(ROOT / "outputs" / "demo_audit_log.json"))
        rt.monitor.check_metrics()
        rt.monitor.export_json(str(ROOT / "outputs" / "demo_metrics.json"))

        return {
            "request_id": request_id,
            "target": target,
            "response": response,
            "blocked": blocked,
            "redacted": redacted,
            "leaked_demo_secret": leaked,
            "layer": layer,
            "guardrails": guardrails,
            "latency_ms": elapsed_ms,
            "metrics": rt.monitor.snapshot(),
        }


@app.post("/api/hitl")
async def hitl(request: ApprovalRequest):
    decision = "approved" if request.decision == "approve" else "rejected"
    rt = _ensure_runtime()
    request_id = str(uuid.uuid4())
    text = f"HITL {decision}: transfer {request.amount} (simulation only)"
    rt.audit.record_input(user_id="human-reviewer", text=text, request_id=request_id)
    rt.audit.record_output(
        user_id="human-reviewer",
        text="No transaction executed.",
        blocked=decision == "rejected",
        layer="human_review",
        request_id=request_id,
    )
    rt.audit.export_json(str(ROOT / "outputs" / "demo_audit_log.json"))
    return {
        "status": decision,
        "message": f"Mô phỏng: yêu cầu chuyển {request.amount} đã được {('phê duyệt' if decision == 'approved' else 'từ chối')}. Không phát sinh giao dịch.",
    }
