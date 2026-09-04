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


def test_cli_validate_exit_codes():
    """SKILL.md 约定的 exit code 契约：0=通过 1=违规 2=错误/语法错误。"""
    import json
    import subprocess
    py = sys.executable
    root = Path(__file__).resolve().parent.parent
    cli = root / "cli.py"

    def run(*argv):
        p = subprocess.run([py, str(cli), *argv], capture_output=True,
                           text=True, encoding="utf-8", cwd=str(root), timeout=30)
        return p.returncode, p.stdout

    # exit 0: 安全代码
    rc, _ = run("validate", "--code", "import secrets\ntoken = secrets.token_urlsafe(32)")
    assert rc == 0
    # exit 1: 违规
    rc, out = run("validate", "--code", "x = eval(input())")
    assert rc == 1
    assert json.loads(out)["violations"]
    # exit 2: 文件不存在
    rc, out = run("validate", "--file", "Z:/no/such/file.py")
    assert rc == 2 and "file not found" in out
    # exit 2: 纯语法错误（回归：曾返回 0/passed，导致未解析代码被记为通过）
    bad = root / ".tmp_syntax_bad.py"
    bad.write_text("def broken(:", encoding="utf-8")
    try:
        rc, out = run("validate", "--file", str(bad))
        assert rc == 2
        data = json.loads(out)
        assert data["syntax_error"] and not data["violations"]
    finally:
        bad.unlink(missing_ok=True)
