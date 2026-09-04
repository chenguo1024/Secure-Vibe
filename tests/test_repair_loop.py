"""tests/test_repair_loop.py — 修复循环 + 日志 + 端到端测试（Mock 后端，不联网）."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.llm_backend import MockBackend, SessionLLM, create_backend  # noqa: E402
from core.logger import SecureLogger, compute_manual_diff  # noqa: E402
from core.repair_loop import generate_secure_code  # noqa: E402
from core.validator import Validator  # noqa: E402

INSECURE_LOGIN = '''```python
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

SECURE_LOGIN = '''```python
import secrets
import sqlite3

def login(username, password):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM users WHERE name=? AND pwd=?", (username, password)).fetchone()
    token = secrets.randbelow(900000) + 100000
    return token
```'''


def test_mock_default_response_triggers_repair():
    """默认 Mock 返回带漏洞代码 → 校验应拦截。"""
    v = Validator("python")
    from core.repair_loop import _extract_code
    code = _extract_code(MockBackend.DEFAULT_RESPONSE)
    result = v.validate(code)
    assert not result.passed
    rule_ids = {x.rule_id for x in result.violations}
    assert {"GEN-001", "GEN-005", "GEN-003", "PY-001"} & rule_ids


def test_repair_loop_converges():
    """第 1 轮返回漏洞代码，第 2 轮返回安全代码 → 循环应在重试内收敛。"""
    backend = MockBackend(responses=[INSECURE_LOGIN, SECURE_LOGIN])
    outcome = generate_secure_code("实现用户登录接口", backend, language="python")
    assert outcome.passed
    assert outcome.total_retries <= 3
    assert len(outcome.rounds) >= 2
    # 最终代码应通过校验
    v = Validator("python")
    assert v.validate(outcome.code).passed


def test_repair_loop_gives_up_after_max_retries():
    """LLM 始终返回漏洞代码 → 重试超限 → needs_human_review + 报告。"""
    backend = MockBackend(responses=[INSECURE_LOGIN] * 10)
    outcome = generate_secure_code(
        "实现用户登录接口", backend, language="python", max_retries=2)
    assert not outcome.passed
    assert outcome.needs_human_review
    assert outcome.total_retries == 2
    assert "需人工修复" in outcome.report
    assert outcome.code  # 仍交付最佳版本


def test_deterministic_fix_for_insecure_random():
    """混合策略：insecure_random 应由确定性替换修复（不走 LLM）。"""
    # 仅含弱随机的代码（其余安全）
    weak = '''```python
import secrets

def make_id():
    import random
    return random.randint(1, 999)
```'''
    backend = MockBackend(responses=[weak])
    outcome = generate_secure_code("生成 ID", backend, language="python", max_retries=3)
    actions = [r.action for r in outcome.rounds]
    assert "deterministic_fix" in actions, f"应触发确定性修复, 实际: {actions}"


def test_session_llm_passthrough():
    """session 后端跟随调用方注入的 LLM。"""
    seen = {}

    def fake_agent_llm(system, user):
        seen["system"] = system
        return SECURE_LOGIN

    backend = SessionLLM(fake_agent_llm)
    outcome = generate_secure_code("登录", backend, language="python")
    assert outcome.passed
    assert "安全编码专家" in seen["system"]


def test_create_backend_factory():
    from core.llm_backend import LLMConfig
    assert isinstance(create_backend(), MockBackend)
    assert isinstance(create_backend(None), MockBackend)
    # config 里 backend=mock 也应正常返回 MockBackend（回归：曾因传 LLMConfig 给 MockBackend 崩溃）
    assert isinstance(create_backend(LLMConfig(backend="mock")), MockBackend)
    import pytest
    with pytest.raises(ValueError):
        create_backend(type("C", (), {"backend": "session"}))  # session 无注入应报错


def test_logger_jsonl_fields():
    """日志字段完整性（JSONL）。"""
    with tempfile.TemporaryDirectory() as td:
        log = SecureLogger(log_dir=Path(td), mask_secrets=True)
        backend = MockBackend(responses=[INSECURE_LOGIN, SECURE_LOGIN])
        outcome = generate_secure_code("登录接口", backend, language="python")
        path = log.log_generation(
            task_description="登录接口", language="python", framework="",
            context="", outcome=outcome, llm_backend="MockBackend")

        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        required = {
            "timestamp", "event", "task_description", "language", "framework",
            "context", "llm_backend", "rounds", "first_generation_code",
            "total_retries", "llm_calls", "final_verdict", "final_code",
            "manually_modified", "manual_diff", "total_elapsed_ms",
        }
        missing = required - set(rec)
        assert not missing, f"日志缺少字段: {missing}"
        assert rec["final_verdict"] == "passed"
        assert rec["total_retries"] == 1
        # 每轮有违规明细
        assert rec["rounds"][0]["violations"]


def test_logger_masks_secrets():
    with tempfile.TemporaryDirectory() as td:
        log = SecureLogger(log_dir=Path(td), mask_secrets=True)
        path = log.log_generation(
            task_description='写代码 API_KEY = "sk-abcdef1234567890abcdef"',
            language="python", outcome=None)
        rec = json.loads(path.read_text(encoding="utf-8").strip())
        # 无论命中哪条掩码规则，原始密钥都不应出现在日志中
        assert "sk-abcdef1234567890abcdef" not in rec["task_description"]
        assert "*" in rec["task_description"]    # 已打码


def test_manual_diff():
    d = compute_manual_diff("a\nb\n", "a\nc\n")
    assert "-b" in d and "+c" in d


def test_end_to_end_malicious_prompt_flow():
    """故意让模型生成不安全代码 → 检测 → 重新生成 → 通过（成功标准 3）。"""
    backend = MockBackend(responses=[INSECURE_LOGIN, INSECURE_LOGIN, SECURE_LOGIN])
    rounds_seen = []

    outcome = generate_secure_code(
        "实现用户登录接口", backend, language="python",
        on_round=lambda r: rounds_seen.append(r.result.passed))

    # 首轮应被拦截
    assert rounds_seen[0] is False
    assert outcome.passed
    assert outcome.total_retries == 2
