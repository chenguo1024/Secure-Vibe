"""tests/test_repair_loop.py — repair loop + logging + end-to-end tests (Mock backend, offline)."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
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
    """The default Mock returns flawed code -> validation must block it."""
    v = Validator("python")
    from core.repair_loop import _extract_code
    code = _extract_code(MockBackend.DEFAULT_RESPONSE)
    result = v.validate(code)
    assert not result.passed
    rule_ids = {x.rule_id for x in result.violations}
    assert {"GEN-001", "GEN-005", "GEN-003", "PY-001"} & rule_ids


def test_repair_loop_converges():
    """Round 1 flawed, round 2 safe -> the loop converges within retries."""
    backend = MockBackend(responses=[INSECURE_LOGIN, SECURE_LOGIN])
    outcome = generate_secure_code("实现用户登录接口", backend, language="python")
    assert outcome.passed
    assert outcome.total_retries <= 3
    assert len(outcome.rounds) >= 2
    # the final code must pass validation
    v = Validator("python")
    assert v.validate(outcome.code).passed


def test_repair_loop_gives_up_after_max_retries():
    """LLM keeps returning flawed code -> retries exhausted -> needs_human_review + report."""
    backend = MockBackend(responses=[INSECURE_LOGIN] * 10)
    outcome = generate_secure_code(
        "实现用户登录接口", backend, language="python", max_retries=2)
    assert not outcome.passed
    assert outcome.needs_human_review
    assert outcome.total_retries == 2
    assert "human review ticket" in outcome.report
    assert "Unfixed violations" in outcome.report
    assert "Alternatives" in outcome.report
    assert outcome.code  # best version still delivered


def test_deterministic_fix_for_insecure_random():
    """Hybrid strategy: insecure_random must be fixed deterministically (without the LLM)."""
    # code containing only weak randomness (otherwise safe)
    weak = '''```python
import secrets

def make_id():
    import random
    return random.randint(1, 999)
```'''
    backend = MockBackend(responses=[weak])
    outcome = generate_secure_code("生成 ID", backend, language="python", max_retries=3)
    actions = [r.action for r in outcome.rounds]
    assert "deterministic_fix" in actions, f"deterministic fix should trigger; got: {actions}"


def test_session_llm_passthrough():
    """The session backend follows the LLM injected by the caller."""
    seen = {}

    def fake_agent_llm(system, user):
        seen["system"] = system
        return SECURE_LOGIN

    backend = SessionLLM(fake_agent_llm)
    outcome = generate_secure_code("登录", backend, language="python")
    assert outcome.passed
    assert "secure-coding expert" in seen["system"]


def test_create_backend_factory():
    from core.llm_backend import LLMConfig
    assert isinstance(create_backend(), MockBackend)
    assert isinstance(create_backend(None), MockBackend)
    # backend=mock in config must also return a MockBackend (regression: passing LLMConfig to MockBackend used to crash)
    assert isinstance(create_backend(LLMConfig(backend="mock")), MockBackend)
    import pytest
    with pytest.raises(ValueError):
        create_backend(type("C", (), {"backend": "session"}))  # session without injection must raise


def test_logger_jsonl_fields():
    """JSONL field completeness."""
    with tempfile.TemporaryDirectory() as td:
        log = SecureLogger(log_dir=Path(td), mask_secrets=True)
        backend = MockBackend(responses=[INSECURE_LOGIN, SECURE_LOGIN])
        outcome = generate_secure_code("登录接口", backend, language="python")
        path = log.log_generation(
        task_description="login endpoint", language="python", framework="",
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
        assert not missing, f"log record missing fields: {missing}"
        assert rec["final_verdict"] == "passed"
        assert rec["total_retries"] == 1
    # every round carries violation details
        assert rec["rounds"][0]["violations"]


def test_logger_masks_secrets():
    with tempfile.TemporaryDirectory() as td:
        log = SecureLogger(log_dir=Path(td), mask_secrets=True)
        path = log.log_generation(
        task_description='write code API_KEY = "sk-abcdef1234567890abcdef"',
            language="python", outcome=None)
        rec = json.loads(path.read_text(encoding="utf-8").strip())
    # whichever mask rule matched, the raw secret must never appear in the log
        assert "sk-abcdef1234567890abcdef" not in rec["task_description"]
        assert "*" in rec["task_description"]    # masked


def test_manual_diff():
    d = compute_manual_diff("a\nb\n", "a\nc\n")
    assert "-b" in d and "+c" in d


def test_end_to_end_malicious_prompt_flow():
    """Deliberately insecure code -> detected -> regenerated -> passing (success criterion 3)."""
    backend = MockBackend(responses=[INSECURE_LOGIN, INSECURE_LOGIN, SECURE_LOGIN])
    rounds_seen = []

    outcome = generate_secure_code(
        "实现用户登录接口", backend, language="python",
        on_round=lambda r: rounds_seen.append(r.result.passed))

    # the first round must be blocked
    assert rounds_seen[0] is False
    assert outcome.passed
    assert outcome.total_retries == 2
