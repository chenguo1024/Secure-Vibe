"""tests/test_ci.py — GitHub Actions workflow rule tests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validator import Validator, normalize_language  # noqa: E402


def validate(code: str, language: str = "github-actions"):
    return Validator(language).validate(code)


def ids(result):
    return {x.rule_id for x in result.violations}


def test_language_normalization_gha():
    assert normalize_language("workflow") == "github-actions"
    assert normalize_language("gha") == "github-actions"
    assert normalize_language("github_actions") == "github-actions"


def test_gha_detects_expression_injection():
    code = 'run: echo "processing ${{ github.event.issue.body }}"'
    assert "GHA-001" in ids(validate(code))


def test_gha_detects_secret_to_log():
    code = 'run: echo "token is ${{ secrets.API_TOKEN }}"'
    assert "GHA-002" in ids(validate(code))


def test_gha_detects_unpinned_action():
    code = "uses: actions/checkout@main"
    assert "GHA-003" in ids(validate(code))


def test_gha_safe_passes():
    code = (
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@3df4ab11eba7bda6032a0b82a6c43e6e6217c490\n"
        "      - name: Test\n"
        "        env:\n"
        "          BODY: ${{ github.event.issue.body }}\n"
        "        run: echo \"$BODY\"\n"
    )
    assert validate(code).passed
