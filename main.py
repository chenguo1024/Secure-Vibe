"""main.py — Secure-Vibe 入口.

函数入口:
    generate_secure_code(task_description, language, framework, context)

CLI:
    python main.py --task "实现用户登录接口" --language python --framework Flask
    python main.py --validate suspicious.py       # 仅校验已有代码
    python main.py --demo                         # Mock 后端端到端演示（不联网）
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

# 支持 python main.py 直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import yaml
    from core.context_builder import build_prompts
    from core.llm_backend import LLMConfig, create_backend
    from core.logger import SecureLogger, compute_manual_diff
    from core.repair_loop import GenerationOutcome, generate_secure_code as _run_generation
    from core.validator import Validator
except ImportError as exc:
    print(f"[Secure-Vibe] 缺少依赖: {exc}\n请先: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = PROJECT_ROOT / "config.yaml"


# ---------------------------------------------------------------------------
# 配置加载
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    """加载 config.yaml，环境变量 SECURE_VIBE_* 可覆盖 llm.backend。"""
    path = config_path or DEFAULT_CONFIG
    cfg: dict[str, Any] = {}
    if path.is_file():
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    # 环境变量覆盖: SECURE_VIBE_LLM_BACKEND=openai
    env_backend = os.environ.get("SECURE_VIBE_LLM_BACKEND")
    if env_backend:
        cfg.setdefault("llm", {})["backend"] = env_backend
    return cfg


# ---------------------------------------------------------------------------
# 核心入口函数
# ---------------------------------------------------------------------------

def generate_secure_code(
    task_description: str,
    language: str = "python",
    framework: str = "",
    context: str = "",
    backend: Optional[Any] = None,          # 已创建的 LLM 后端；None 则按 config 创建
    session_fn: Optional[Callable[[str, str], str]] = None,
    config_path: Optional[Path] = None,
    logger: Optional[SecureLogger] = None,
    on_round: Optional[Callable[[Any], None]] = None,
    validate_only_rules: bool = False,
) -> GenerationOutcome:
    """生成"安全代码"——生成时引导，校验不通过自动修复。

    这是给调用方（脚本 / Agent / HTTP 服务）使用的主入口。
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
    backend = backend or create_backend(llm_cfg, session_fn=session_fn)

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
    """仅校验：对已有代码做实时安全校验（不生成、不修复）。"""
    cfg = load_config()
    ignore = ignore_rules or (cfg.get("validator", {}) or {}).get("ignore_rules", [])
    v = Validator(language=language, ignore_rules=ignore)
    return v.validate(code)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_demo() -> int:
    """端到端演示：Mock 后端返回带漏洞代码 → 校验器拦截 → 修复循环。不联网。"""
    print("=" * 64)
    print("Secure-Vibe 端到端演示（Mock 后端，不联网）")
    print("=" * 64)

    def mock_script(system: str, user: str, call_idx: int) -> str:
        # 第 1 次调用返回带漏洞代码；修复轮返回修复后的代码
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
        task_description="实现用户登录接口",
        language="python",
        framework="sqlite",
        backend=MockBackend(script=mock_script),
    )
    print()
    print(outcome.summary())
    print()
    print("--- 最终代码 ---")
    print(outcome.code)
    if outcome.report:
        print()
        print(outcome.report)
    print()
    print("日志已写入 logs/ 目录（JSONL 格式）")
    return 0 if outcome.passed else 1


def _cmd_validate(path: str) -> int:
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    result = validate_code(code)
    print(result.summary())
    print(f"\n耗时: {result.elapsed_ms:.1f}ms")
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
    ap = argparse.ArgumentParser(prog="secure-vibe", description="生成时安全的代码生成 Skill")
    ap.add_argument("--task", help="任务描述")
    ap.add_argument("--language", default="python", help="目标语言（默认 python）")
    ap.add_argument("--framework", default="", help="框架，如 Flask / FastAPI")
    ap.add_argument("--context", default="", help="上下文补充说明（文本或文件路径）")
    ap.add_argument("--validate", metavar="FILE", help="仅校验指定代码文件")
    ap.add_argument("--demo", action="store_true", help="运行端到端 Mock 演示")
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
