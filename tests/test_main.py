"""tests/test_main.py — 入口函数行为测试."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402


def test_validate_code_returns_result():
    result = main.validate_code("eval(user_input)")
    assert not result.passed
    assert any(v.rule_id == "PY-001" for v in result.violations)


def test_generate_without_backend_does_not_crash():
    """回归：config 默认 backend=session 且未注入 session_fn 时，
    应优雅降级为 mock 而非抛 ValueError（曾导致 main.py --task 崩溃）。"""
    outcome = main.generate_secure_code(task_description="返回两数之和")
    assert outcome is not None
    assert hasattr(outcome, "passed")
    # 无后端注入时走了 mock（返回的是预置代码），结果要么通过要么需人工修复，但绝不应抛异常
    assert outcome.passed or outcome.needs_human_review


def test_validate_safe_code_passes():
    result = main.validate_code("import secrets\ntoken = secrets.token_urlsafe(32)")
    assert result.passed
