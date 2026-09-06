"""tests/test_context_builder.py — Security context builder tests."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.context_builder import build_prompts, build_repair_prompt  # noqa: E402


def test_prompt_contains_all_sections():
    system, user = build_prompts("实现用户登录接口", "python", "Flask")
    # persona
    assert "secure-coding expert" in system
    # general rules
    assert "General security rules" in system
    assert "GEN-001" in system          # hardcoded secret rule
    # language rules
    assert "python-specific rules" in system.lower()
    assert "PY-001" in system           # eval/exec rule
    # blacklist
    assert "Banned-pattern blacklist" in system
    # few-shot template (a login task should trigger the auth template)
    assert "Safe example" in system
    # checklist
    assert "Self-check" in system
    # user prompt (Chinese task description is user input, passed through as-is)
    assert "实现用户登录接口" in user
    assert "Flask" in user


def test_few_shot_matches_task_keywords():
    # db task -> db_query template
    system, _ = build_prompts("写一个数据库查询函数", "python")
    assert "db_query" in system
    # token task -> secure_token template
    system, _ = build_prompts("生成随机 token", "python")
    assert "secure_token" in system


def test_repair_prompt_contains_violations():
    p = build_repair_prompt("eval(x)", "FAIL: 1 violation detected", "python")
    assert "failed the security validation" in p
    assert "FAIL: 1 violation detected" in p
    assert "eval(x)" in p
    assert "regenerate" in p
