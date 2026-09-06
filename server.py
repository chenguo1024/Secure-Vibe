"""server.py — Secure-Vibe HTTP API (optional service mode).

Run:
    pip install fastapi uvicorn
    uvicorn server:app --port 8399
    # or: python server.py

Endpoints:
    POST /generate   {task, language, framework, context, backend?}
    POST /validate   {code, language}
    POST /feedback   {pattern, note?}      # missed-pattern report (rule-iteration material)
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
              description="Secure-by-generation coding skill - HTTP API")

_logger = SecureLogger()
_cfg = load_config()


class GenerateRequest(BaseModel):
    task: str = Field(..., min_length=1, description="task description")
    language: str = "python"
    framework: str = ""
    context: str = ""
    backend: str = ""  # overrides config.yaml llm.backend (e.g. openai/claude/mock)


class ValidateRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = "python"


class FeedbackRequest(BaseModel):
    pattern: str = Field(..., min_length=1, description="description/code snippet of the missed attack pattern")
    note: str = ""
    severity: str = "medium"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "secure-vibe"}


@app.post("/generate")
def generate(req: GenerateRequest) -> dict[str, Any]:
    """Generate secure code; automatically enters the repair loop on validation failure."""
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
    except Exception as exc:  # LLM backend errors, etc.
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
    """Validate existing code only (no generation)."""
    result = validate_code(req.code, req.language)
    return result.to_dict()


@app.post("/feedback")
def feedback(req: FeedbackRequest) -> dict[str, str]:
    """Missed-pattern report -> recorded to the log, to be promoted to an official rule after human review (rule-iteration loop)."""
    path = _logger.log_missed_pattern(req.pattern, note=req.note, severity=req.severity)
    return {"status": "recorded", "log": str(path)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8399)
