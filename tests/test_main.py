"""tests/test_main.py — entry-function behavior tests."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402


def test_validate_code_returns_result():
    result = main.validate_code("eval(user_input)")
    assert not result.passed
    assert any(v.rule_id == "PY-001" for v in result.violations)


def test_generate_without_backend_does_not_crash():
    """Regression: with the default backend=session and no session_fn injected, the call must
    gracefully degrade to mock instead of raising ValueError (used to crash main.py --task)."""
    outcome = main.generate_secure_code(task_description="返回两数之和")
    assert outcome is not None
    assert hasattr(outcome, "passed")
    # with no backend injected the mock runs (preset code); the outcome passes or needs human
    # review - but must never raise
    assert outcome.passed or outcome.needs_human_review


def test_validate_safe_code_passes():
    result = main.validate_code("import secrets\ntoken = secrets.token_urlsafe(32)")
    assert result.passed


def test_cli_validate_exit_codes():
    """The exit-code contract promised by SKILL.md: 0=pass 1=violations 2=error/syntax."""
    import json
    import subprocess
    py = sys.executable
    root = Path(__file__).resolve().parent.parent
    cli = root / "cli.py"

    def run(*argv):
        p = subprocess.run([py, str(cli), *argv], capture_output=True,
                           text=True, encoding="utf-8", cwd=str(root), timeout=30)
        return p.returncode, p.stdout

    # exit 0: safe code
    rc, _ = run("validate", "--code", "import secrets\ntoken = secrets.token_urlsafe(32)")
    assert rc == 0
    # exit 1: violations
    rc, out = run("validate", "--code", "x = eval(input())")
    assert rc == 1
    assert json.loads(out)["violations"]
    # exit 2: file not found
    rc, out = run("validate", "--file", "Z:/no/such/file.py")
    assert rc == 2 and "file not found" in out
    # exit 2: pure syntax error (regression: it used to return 0/passed, logging unparsable code as passing)
    bad = root / ".tmp_syntax_bad.py"
    bad.write_text("def broken(:", encoding="utf-8")
    try:
        rc, out = run("validate", "--file", str(bad))
        assert rc == 2
        data = json.loads(out)
        assert data["syntax_error"] and not data["violations"]
    finally:
        bad.unlink(missing_ok=True)
