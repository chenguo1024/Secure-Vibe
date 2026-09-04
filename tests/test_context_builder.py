"""tests/test_context_builder.py — 安全上下文构建器测试."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.context_builder import build_prompts, build_repair_prompt  # noqa: E402


def test_prompt_contains_all_sections():
    system, user = build_prompts("实现用户登录接口", "python", "Flask")
    # 角色设定
    assert "安全编码专家" in system
    # 通用规则
    assert "通用安全规则" in system
    assert "GEN-001" in system          # 硬编码密钥规则
    # 语言规则
    assert "python 特定规则" in system.lower() or "Python 特定规则" in system
    assert "PY-001" in system           # eval/exec 规则
    # 黑名单
    assert "禁用模式黑名单" in system
    # few-shot 模板（登录任务应触发 auth 模板）
    assert "安全示例" in system
    # 自检清单
    assert "自检" in system
    # user prompt
    assert "实现用户登录接口" in user
    assert "Flask" in user


def test_few_shot_matches_task_keywords():
    # db 任务 → db_query 模板
    system, _ = build_prompts("写一个数据库查询函数", "python")
    assert "db_query" in system
    # token 任务 → secure_token 模板
    system, _ = build_prompts("生成随机 token", "python")
    assert "secure_token" in system


def test_repair_prompt_contains_violations():
    p = build_repair_prompt("eval(x)", "FAIL: 检测到 1 处违规", "python")
    assert "未通过安全校验" in p
    assert "FAIL: 检测到 1 处违规" in p
    assert "eval(x)" in p
    assert "重新生成" in p
