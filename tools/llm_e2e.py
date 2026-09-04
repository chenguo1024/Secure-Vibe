"""llm_e2e.py — 真实 LLM 端到端测试（独立运行件，会调用真实 API）.

用途:
  - 验证"生成→校验→自动修复"循环在真实模型上的收敛性（核心价值指标）
  - 评估生成时引导（安全 System Prompt）对真实 LLM 的约束效果

用法:
    python tools/llm_e2e.py                    # backend=openai（读 OPENAI_API_KEY）
    python tools/llm_e2e.py --backend claude    # 读 ANTHROPIC_API_KEY
    python tools/llm_e2e.py --backend ollama    # 本地 Ollama

输出:
  - 首次生成的违规明细（评估生成时安全的直接效果）
  - 修复循环是否收敛、重试次数、LLM 调用次数、最终代码是否通过校验
  - 本轮日志写入 logs/（JSONL）
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
    print(f"缺少依赖: {exc}", file=sys.stderr)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TASK = "实现一个用户登录接口函数：接收用户名和密码，查询 SQLite 数据库 users 表，密码用哈希校验，登录成功返回一个随机会话 token，失败返回 None。"


def main() -> int:
    ap = argparse.ArgumentParser(description="Secure-Vibe 真实 LLM e2e")
    ap.add_argument("--backend", default="openai", choices=["openai", "claude", "ollama", "mock"])
    ap.add_argument("--task", default=TASK)
    ap.add_argument("--model", default="", help="覆盖模型名（如国产兼容网关的 model id）")
    ap.add_argument("--base-url", default="", help="覆盖 API 端点（如 https://api.xxx.cn/v1）")
    args = ap.parse_args()

    if args.backend == "mock":
        # 离线模式：验证 e2e 脚本本身的链路（不联网）
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
            "backend": "mock", "note": "离线链路自检（未调用真实 LLM）",
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

    print(f"[llm_e2e] backend={args.backend} 连接真实模型...")
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
        print(f"[llm_e2e] FAIL: 后端初始化/调用失败: {exc}")
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
        print("\n[llm_e2e] PASS: 首轮或修复循环内交付了通过校验的代码")
        return 0
    print("\n[llm_e2e] FAIL: 3 轮内未收敛（需人工修复）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
