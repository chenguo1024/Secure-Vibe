"""main.py — Secure-Vibe entry point.
# secure-vibe: ignore-file - demo contains deliberate flawed code (teaching example)

Function API:
    generate_secure_code(task_description, language, framework, context)

CLI:
    python main.py --task "implement user login endpoint" --language python --framework Flask
    python main.py --validate suspicious.py       # validate existing code only
    python main.py --demo                         # offline end-to-end demo on the Mock backend
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

# so `python main.py` works directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import yaml
    from core.context_builder import build_prompts
    from core.llm_backend import LLMConfig, create_backend
    from core.logger import SecureLogger, compute_manual_diff
    from core.repair_loop import GenerationOutcome, generate_secure_code as _run_generation
    from core.validator import Validator
except ImportError as exc:
    print(f"[Secure-Vibe] missing dependency: {exc}\nrun: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = PROJECT_ROOT / "config.yaml"


# ---------------------------------------------------------------------------
# config loading
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    """Load config.yaml; env var SECURE_VIBE_* overrides llm.backend."""
    path = config_path or DEFAULT_CONFIG
    cfg: dict[str, Any] = {}
    if path.is_file():
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    # environment override: SECURE_VIBE_LLM_BACKEND=openai
    env_backend = os.environ.get("SECURE_VIBE_LLM_BACKEND")
    if env_backend:
        cfg.setdefault("llm", {})["backend"] = env_backend
    return cfg


# ---------------------------------------------------------------------------
# core entry functions
# ---------------------------------------------------------------------------

def generate_secure_code(
    task_description: str,
    language: str = "python",
    framework: str = "",
    context: str = "",
    backend: Optional[Any] = None,          # pre-built LLM backend; None builds one from config
    session_fn: Optional[Callable[[str, str], str]] = None,
    config_path: Optional[Path] = None,
    logger: Optional[SecureLogger] = None,
    on_round: Optional[Callable[[Any], None]] = None,
    validate_only_rules: bool = False,
) -> GenerationOutcome:
    """Generate "secure code" — guided at generation time with automatic repair on validation failure.

    This is the main entry point for callers (scripts / agents / HTTP services).
    """
    cfg = load_config(config_path)
    llm_cfg = LLMConfig(
        backend=(cfg.get("llm", {}) or {}).get("backend", "mock"),
        model=(cfg.get("llm", {}) or {}).get("model", ""),
        temperature=(cfg.get("llm", {}) or {}).get("temperature", 0.2),
        max_tokens=(cfg.get("llm", {}) or {}).get("max_tokens", 2048),
        timeout=(cfg.get("llm", {}) or {}).get("timeout", 60),
        base_url=(cfg.get("llm", {}) or {}).get("base_url", ""),
    )
    repair_cfg = cfg.get("repair", {}) or {}
    if backend is None:
        # the session backend must be injected via session_fn; without it, gracefully
        # fall back to mock (works out of the box; agents normally enter via cli.py)
        if llm_cfg.backend == "session" and session_fn is None:
            llm_cfg.backend = "mock"
            print("[Secure-Vibe] note: no session_fn injected; session backend falls back to mock "
                  "(override with SECURE_VIBE_LLM_BACKEND)", file=sys.stderr)
        backend = create_backend(llm_cfg, session_fn=session_fn)

    if logger is None:
        log_cfg = cfg.get("logging", {}) or {}
        logger = SecureLogger(
            log_dir=PROJECT_ROOT / log_cfg.get("dir", "logs"),
            mask_secrets=log_cfg.get("mask_secrets", True),
            log_code=log_cfg.get("log_code", True),
        )

    outcome = _run_generation(
        task_description=task_description,
        backend=backend,
        language=language,
        framework=framework,
        context=context,
        max_retries=repair_cfg.get("max_retries", 3),
        strategy=repair_cfg.get("strategy", "hybrid"),
        on_round=on_round,
    )

    logger.log_generation(
        task_description=task_description,
        language=language,
        framework=framework,
        context=context,
        outcome=outcome,
        llm_backend=type(backend).__name__,
    )
    return outcome


def validate_code(code: str, language: str = "python",
                  ignore_rules: Optional[list[str]] = None) -> Any:
    """Validate only: real-time security validation of existing code (no generation, no repair)."""
    cfg = load_config()
    ignore = ignore_rules or (cfg.get("validator", {}) or {}).get("ignore_rules", [])
    v = Validator(language=language, ignore_rules=ignore)
    return v.validate(code)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_demo() -> int:
    """End-to-end demo: Mock backend returns flawed code -> the validator blocks it -> repair loop. Offline."""
    print("=" * 64)
    print("Secure-Vibe end-to-end demo (Mock backend, offline)")
    print("=" * 64)

    def mock_script(system: str, user: str, call_idx: int) -> str:
        # first call returns flawed code; repair rounds return the fixed code
        if call_idx == 0:
            return '''```python
import sqlite3
import random
API_KEY = "sk-hardcoded-secret-key-123456"

def login(username, password):
    conn = sqlite3.connect("app.db")
    sql = f"SELECT * FROM users WHERE name='{username}' AND pwd='{password}'"
    row = conn.execute(sql).fetchone()
    token = random.randint(100000, 999999)
    return token
```'''
        return '''```python
import os
import secrets
import sqlite3

def login(username, password):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM users WHERE name=? AND pwd=?", (username, password)).fetchone()
    token = secrets.randbelow(900000) + 100000
    return token
```'''

    from core.llm_backend import MockBackend
    outcome = generate_secure_code(
        task_description="implement user login endpoint",
        language="python",
        framework="sqlite",
        backend=MockBackend(script=mock_script),
    )
    print()
    print(outcome.summary())
    print()
    print("--- final code ---")
    print(outcome.code)
    if outcome.report:
        print()
        print(outcome.report)
    print()
    print("log written to the logs/ directory (JSONL format)")
    return 0 if outcome.passed else 1


def _cmd_validate(path: str) -> int:
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    result = validate_code(code)
    print(result.summary())
    print(f"\nelapsed: {result.elapsed_ms:.1f}ms")
    return 0 if result.passed else 1


def _cmd_generate(args: argparse.Namespace) -> int:
    context = ""
    if args.context and Path(args.context).is_file():
        context = Path(args.context).read_text(encoding="utf-8", errors="replace")
    else:
        context = args.context or ""
    outcome = generate_secure_code(
        task_description=args.task,
        language=args.language,
        framework=args.framework,
        context=context,
    )
    print(outcome.summary())
    print()
    print(outcome.code if outcome.passed else outcome.report)
    return 0 if outcome.passed else 1


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="secure-vibe", description="Secure-by-generation coding skill")
    ap.add_argument("--task", help="task description")
    ap.add_argument("--language", default="python", help="target language (default python)")
    ap.add_argument("--framework", default="", help="framework, e.g. Flask / FastAPI")
    ap.add_argument("--context", default="", help="additional context (text or a file path)")
    ap.add_argument("--validate", metavar="FILE", help="validate the given code file only")
    ap.add_argument("--demo", action="store_true", help="run the end-to-end Mock demo")
    args = ap.parse_args(argv)

    if args.demo:
        return _cmd_demo()
    if args.validate:
        return _cmd_validate(args.validate)
    if args.task:
        return _cmd_generate(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
