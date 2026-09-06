"""logger.py — JSONL logger.

Each record is one line of JSON written to logs/<date>.jsonl.
Field spec: docs/log_format.md.

Usage:
    from core.logger import SecureLogger
    log = SecureLogger()                      # default logs/ directory
    log.log_generation(task=..., language=..., outcome=..., ...)
"""
from __future__ import annotations

import difflib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# suspected-secret masking patterns (paired with logging.mask_secrets)
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*[\"'][^\"']{6,}[\"']"),
    re.compile(r"(sk-[A-Za-z0-9_-]{20,})"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
]


def _mask(text: str) -> str:
    """Mask suspected secrets: keep first 3 and last 2 chars."""
    def repl(m: re.Match) -> str:
        s = m.group(0)
        if len(s) <= 8:
            return s
        return s[:3] + "*" * (len(s) - 5) + s[-2:]
    out = text
    for p in _SECRET_PATTERNS:
        out = p.sub(repl, out)
    return out


def compute_manual_diff(original: str, modified: str) -> str:
    """Compute the unified diff of a manual edit (for the manual_diff log field)."""
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile="generated", tofile="manual",
    ))


class SecureLogger:
    """JSONL logger. Thread-safe (append-mode writes; line-level atomicity is an OS guarantee)."""

    def __init__(self, log_dir: Optional[Path] = None,
                 filename_pattern: str = "%Y-%m-%d.jsonl",
                 mask_secrets: bool = True, log_code: bool = True):
        self.log_dir = Path(log_dir) if log_dir else PROJECT_ROOT / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.filename_pattern = filename_pattern
        self.mask_secrets = mask_secrets
        self.log_code = log_code

    @property
    def log_file(self) -> Path:
        return self.log_dir / datetime.now().strftime(self.filename_pattern)

    def _write(self, record: dict[str, Any]) -> Path:
        if self.mask_secrets:
            record = {k: _mask(v) if isinstance(v, str) else v for k, v in record.items()}
        path = self.log_file
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        return path

    # -- generation records ---------------------------------------------------

    def log_generation(
        self,
        task_description: str,
        language: str,
        framework: str = "",
        context: str = "",
        outcome: Any = None,           # GenerationOutcome
        llm_backend: str = "",
        manually_modified: bool = False,
        manual_diff: str = "",
        extra: Optional[dict[str, Any]] = None,
    ) -> Path:
        """Record one complete generation process (including per-round details)."""
        rounds = []
        for r in getattr(outcome, "rounds", []):
            rounds.append({
                "round_no": r.round_no,
                "action": r.action,
                "passed": r.result.passed,
                "violations": [v.to_dict() for v in r.result.violations],
                "elapsed_ms": round(r.result.elapsed_ms, 3),
                "code": r.code if self.log_code else f"<{len(r.code)} chars>",
            })
        final_code = getattr(outcome, "code", "")
        record = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "event": "generation",
            "task_description": task_description,
            "language": language,
            "framework": framework,
            "context": context,
            "llm_backend": llm_backend,
            "rounds": rounds,
            "first_generation_code": rounds[0]["code"] if rounds else "",
            "total_retries": getattr(outcome, "total_retries", 0),
            "llm_calls": getattr(outcome, "llm_calls", 0),
            "final_verdict": "passed" if getattr(outcome, "passed", False)
                             else ("needs_human_review" if getattr(outcome, "needs_human_review", False)
                                   else "failed"),
            "final_code": final_code if self.log_code else f"<{len(final_code)} chars>",
            "report": getattr(outcome, "report", ""),
            "total_elapsed_ms": round(getattr(outcome, "total_elapsed_ms", 0.0), 3),
            "manually_modified": manually_modified,
            "manual_diff": manual_diff,
        }
        if extra:
            record.update(extra)
        return self._write(record)

    # -- missed/bypass records (feeds the rule-iteration loop) -----------------

    def log_missed_pattern(
        self,
        pattern: str,
        source_code: str = "",
        note: str = "",
        severity: str = "medium",
    ) -> Path:
        """Record a new attack pattern the validator missed/was bypassed by — material for blacklist/pending.yaml.

        After human review it can be promoted to an official rule (anti-poisoning review gate preserved).
        """
        record = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "event": "missed_pattern",
            "pattern": pattern,
            "source_code": source_code[:2000],
            "note": note,
            "severity": severity,
            "status": "pending_review",
        }
        return self._write(record)

    # -- human-approved promotion record ---------------------------------------

    def log_rule_promoted(self, rule_id: str, rule_yaml: str, note: str = "") -> Path:
        record = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "event": "rule_promoted",
            "rule_id": rule_id,
            "rule_yaml": rule_yaml,
            "note": note,
        }
        return self._write(record)
