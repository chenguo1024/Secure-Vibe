"""llm_e2e.py — Real-LLM end-to-end test (calls a real model; needs a real API).

Purpose:
  - verify the generate->validate->auto-repair loop with a real model (research-grade value metric)
  - when changes are needed: review the full system prompt and debug the constraints against a real LLM

Usage:
    python tools/llm_e2e.py                    # backend=openai (needs OPENAI_API_KEY)
    python tools/llm_e2e.py --backend claude   # needs ANTHROPIC_API_KEY
    python tools/llm_e2e.py --backend ollama   # local Ollama

Output:
  - first-generation violation details, repair-round interactions, hard metrics for the whole run
  - whether the repair loop converges, how many LLM calls were made, whether the final code passes
  - full log written to logs/ (JSONL)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yaml
    from core.llm_backend import LLMConfig, create_backend
    from core.repair_loop import generate_secure_code
    from core.validator import Validator
except ImportError as exc:
    print(f"missing dependency: {exc}", file=sys.stderr)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TASK = "Implement a user login endpoint — a function that takes username and password, queries the users table in SQLite and verifies the hash; on success return a secure session token, on failure return None."


def main() -> int:
    ap = argparse.ArgumentParser(description="Secure-Vibe real-LLM e2e")
    ap.add_argument("--backend", default="openai", choices=["openai", "claude", "ollama", "mock"])
    ap.add_argument("--task", default=TASK)
    ap.add_argument("--model", default="", help="model override (any compatible model id)")
    ap.add_argument("--base-url", default="", help="API endpoint override (e.g. https://api.xxx.cn/v1)")
    args = ap.parse_args()

    if args.backend == "mock":
    # mock mode: verify the e2e script's own pipeline correctness
        from core.llm_backend import MockBackend
        INSECURE = '''```python
import sqlite3
import random
API_KEY = "sk-hardcoded-secret-key-1234567890"

def login(username, password):
    conn = sqlite3.connect("app.db")
    sql = f"SELECT * FROM users WHERE name='{username}' AND pwd='{password}'"
    row = conn.execute(sql).fetchone()
    token = random.randint(100000, 999999)
    return token
```'''
        SECURE = '''```python
import os
import secrets
import sqlite3

def login(username, password):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM users WHERE name=? AND pwd=?", (username, password)).fetchone()
    token = secrets.randbelow(900000) + 100000
    return token
```'''
        backend = MockBackend(script=lambda s, u, i: INSECURE if i == 0 else SECURE)
        outcome = generate_secure_code(args.task, backend, language="python",
                                       framework="sqlite", max_retries=3)
        print(json.dumps({
            "backend": "mock", "note": "offline pipeline self-check (no real LLM call)",
            "first_round_passed": outcome.rounds[0].result.passed,
            "first_round_violations": [v.rule_id for v in outcome.rounds[0].result.violations],
            "repair_converged": outcome.passed,
            "total_retries": outcome.total_retries,
        }, ensure_ascii=False, indent=1))
        return 0 if outcome.passed else 1

    cfg_path = PROJECT_ROOT / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {} if cfg_path.is_file() else {}
    llm = cfg.get("llm", {}) or {}
    llm_cfg = LLMConfig(
        backend=args.backend,
        model=args.model or llm.get("model", ""),
        temperature=llm.get("temperature", 0.2),
        max_tokens=llm.get("max_tokens", 2048),
        timeout=llm.get("timeout", 60),
        base_url=args.base_url or llm.get("base_url", ""),
    )

    print(f"[llm_e2e] backend={args.backend} calling the real model...")
    t0 = time.time()
    try:
        backend = create_backend(llm_cfg)
        outcome = generate_secure_code(
            task_description=args.task,
            backend=backend,
            language="python",
            framework="sqlite",
            max_retries=3,
        )
    except Exception as exc:
        print(f"[llm_e2e] FAIL: init/call failed: {exc}")
        return 2

    elapsed = time.time() - t0
    first = outcome.rounds[0]
    first_violations = [v.to_dict() for v in first.result.violations]
    print(json.dumps({
        "backend": args.backend,
        "task": args.task[:60] + "...",
        "first_round_passed": first.result.passed,
        "first_round_violations": first_violations,
        "repair_converged": outcome.passed,
        "needs_human_review": outcome.needs_human_review,
        "total_retries": outcome.total_retries,
        "llm_calls": outcome.llm_calls,
        "rounds": len(outcome.rounds),
        "elapsed_s": round(elapsed, 1),
        "final_code": outcome.code[:400],
    }, ensure_ascii=False, indent=1))

    if outcome.passed:
        print("\n[llm_e2e] PASS: the repair loop converged and produced validation-passing code")
        return 0
    print("\n[llm_e2e] FAIL: did not converge within 3 rounds (needs human review)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
