"""logger.py — JSONL 日志记录器.

每条记录一行 JSON，写入 logs/<日期>.jsonl。
字段规范见 docs/log_format.md。

用法:
    from core.logger import SecureLogger
    log = SecureLogger()                      # 默认 logs/ 目录
    log.log_generation(task=..., language=..., outcome=..., ...)
"""
from __future__ import annotations

import difflib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 疑似密钥的掩码模式（配合 logging.mask_secrets）
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*[\"'][^\"']{6,}[\"']"),
    re.compile(r"(sk-[A-Za-z0-9_-]{20,})"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
]


def _mask(text: str) -> str:
    """对疑似密钥打码: 保留前 3 后 2 字符。"""
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
    """计算人工修改的 unified diff（供日志字段 manual_diff）。"""
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile="generated", tofile="manual",
    ))


class SecureLogger:
    """JSONL 日志记录器。线程安全（文件追加 + 行级原子性由 OS 保证）。"""

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

    # -- 生成记录 -----------------------------------------------------------

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
        """记录一次完整的生成过程（含每轮明细）。"""
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

    # -- 漏检/绕过记录（用于规则迭代闭环） -----------------------------------

    def log_missed_pattern(
        self,
        pattern: str,
        source_code: str = "",
        note: str = "",
        severity: str = "medium",
    ) -> Path:
        """记录校验器漏检/被绕过的新攻击模式 → blacklist/pending.yaml 素材。

        人工审核后可升级为正式规则（防投毒，保留审核闸口）。
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

    # -- 人工审核通过记录 -----------------------------------------------------

    def log_rule_promoted(self, rule_id: str, rule_yaml: str, note: str = "") -> Path:
        record = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "event": "rule_promoted",
            "rule_id": rule_id,
            "rule_yaml": rule_yaml,
            "note": note,
        }
        return self._write(record)
