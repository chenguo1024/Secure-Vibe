"""server.py — Secure-Vibe HTTP API（可选服务模式）.

启动:
    pip install fastapi uvicorn
    uvicorn server:app --port 8399
    # 或: python server.py

端点:
    POST /generate   {task, language, framework, context, backend?}
    POST /validate   {code, language}
    POST /feedback   {pattern, note?}      # 漏检模式上报（规则迭代闭环素材）
    GET  /health
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from core.logger import SecureLogger
from main import generate_secure_code, load_config, validate_code

app = FastAPI(title="Secure-Vibe", version="1.0",
              description="生成时安全的代码生成 Skill — HTTP API")

_logger = SecureLogger()
_cfg = load_config()


class GenerateRequest(BaseModel):
    task: str = Field(..., min_length=1, description="任务描述")
    language: str = "python"
    framework: str = ""
    context: str = ""
    backend: str = ""  # 覆盖 config.yaml 的 llm.backend（如 openai/claude/mock）


class ValidateRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = "python"


class FeedbackRequest(BaseModel):
    pattern: str = Field(..., min_length=1, description="漏检的攻击模式描述/代码片段")
    note: str = ""
    severity: str = "medium"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "secure-vibe"}


@app.post("/generate")
def generate(req: GenerateRequest) -> dict[str, Any]:
    """生成安全代码。校验不通过时自动进入修复循环。"""
    import os
    old = None
    if req.backend:
        old = os.environ.get("SECURE_VIBE_LLM_BACKEND")
        os.environ["SECURE_VIBE_LLM_BACKEND"] = req.backend
    try:
        outcome = generate_secure_code(
            task_description=req.task,
            language=req.language,
            framework=req.framework,
            context=req.context,
            logger=_logger,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # LLM 后端异常等
        raise HTTPException(status_code=502, detail=f"generation failed: {exc}") from exc
    finally:
        if req.backend:
            if old is None:
                os.environ.pop("SECURE_VIBE_LLM_BACKEND", None)
            else:
                os.environ["SECURE_VIBE_LLM_BACKEND"] = old

    return {
        "passed": outcome.passed,
        "needs_human_review": outcome.needs_human_review,
        "total_retries": outcome.total_retries,
        "llm_calls": outcome.llm_calls,
        "elapsed_ms": round(outcome.total_elapsed_ms, 1),
        "code": outcome.code,
        "report": outcome.report or None,
        "violations_final": [v.to_dict() for v in outcome.rounds[-1].result.violations],
    }


@app.post("/validate")
def validate(req: ValidateRequest) -> dict[str, Any]:
    """仅校验已有代码（不生成）。"""
    result = validate_code(req.code, req.language)
    return result.to_dict()


@app.post("/feedback")
def feedback(req: FeedbackRequest) -> dict[str, str]:
    """漏检模式上报 → 记录到日志，供人工审核后升级为正式规则（规则迭代闭环）。"""
    path = _logger.log_missed_pattern(req.pattern, note=req.note, severity=req.severity)
    return {"status": "recorded", "log": str(path)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8399)
