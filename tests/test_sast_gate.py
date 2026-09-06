"""tests/test_sast_gate.py — sast orchestrator + precommit + regression + selftest suite."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.sast import SastFinding, run_sast, _detect_lang, _walk  # noqa: E402
from core.regression import detect_ecosystem, run_regression  # noqa: E402
from core.selftest_suite import run_suite  # noqa: E402

PY = sys.executable
REPO = Path(__file__).resolve().parent.parent


def _git(*args, cwd=None):
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd)


# --- sast ----------------------------------------------------------------------

def test_detect_lang_map():
    assert _detect_lang(Path("a.py")) == "python"
    assert _detect_lang(Path("b.js")) == "js"
    assert _detect_lang(Path("Dockerfile")) == "dockerfile"
    assert _detect_lang(Path("x.tf")) == "terraform"
    assert _detect_lang(Path("main.go")) == "go"
    assert _detect_lang(Path("notes.txt")) is None


def test_run_sast_finds_violations(tmp_path):
    (tmp_path / "bad.py").write_text("x = eval(user_input)\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("import json\nx = json.loads(raw)\n", encoding="utf-8")
    r = run_sast(tmp_path, run_semgrep_flag=False, run_deps_flag=False)
    assert r.files_scanned == 2
    assert not r.passed
    assert any(f.rule_id == "PY-001" for f in r.findings)
    assert r.engines["builtin"]["ran"]


def test_run_sast_clean_project_passes(tmp_path):
    (tmp_path / "good.py").write_text("import secrets\nt = secrets.token_urlsafe(32)\n", encoding="utf-8")
    r = run_sast(tmp_path, run_semgrep_flag=False, run_deps_flag=False)
    assert r.passed


def test_ignore_file_marker(tmp_path):
    (tmp_path / "fixture.py").write_text(
        "# secure-vibe: ignore-file - deliberate test fixture\nx = eval(user_input)\n",
        encoding="utf-8")
    r = run_sast(tmp_path, run_semgrep_flag=False, run_deps_flag=False)
    assert r.passed, "ignore-file marker must suppress fixture findings"


def test_walk_skips_common_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x.py").write_text("eval(a)\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "y.js").write_text("eval(a);\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("import json\n", encoding="utf-8")
    files = _walk(tmp_path)
    assert len(files) == 1 and files[0][0].name == "keep.py"


def test_sast_yaml_iac_detection(tmp_path):
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: x\n    image: nginx\n"
        "    securityContext:\n      privileged: true\n", encoding="utf-8")
    r = run_sast(tmp_path, run_semgrep_flag=False, run_deps_flag=False)
    assert not r.passed
    assert any(f.rule_id.startswith(("K8S", "DOCK", "TF", "GHA")) for f in r.findings)


# --- precommit (CLI) -------------------------------------------------------------

def test_precommit_flagged_staged_file():
    # repo root is a git repo; stage nothing -> clean run
    r = subprocess.run([PY, str(REPO / "cli.py"), "precommit", "--fail-on", "high"],
                       capture_output=True, text=True, encoding="utf-8", cwd=str(REPO))
    assert r.returncode in (0, 1)   # clean or findings, not an error
    d = json.loads(r.stdout)
    assert d["ok"]


# --- regression ------------------------------------------------------------------

def test_regression_no_suite(tmp_path):
    res = run_regression(tmp_path)
    assert not res.ran
    assert "no test suite" in res.reason


def test_regression_detects_pytest(tmp_path):
    (tmp_path / "tests").mkdir()
    res = detect_ecosystem(tmp_path)
    assert res[0] == "python"


def test_regression_detects_go(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    assert detect_ecosystem(tmp_path)[0] == "go"


def test_regression_detects_node(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"test": "echo ok"}}', encoding="utf-8")
    assert detect_ecosystem(tmp_path)[0] == "node"


# --- selftest suite ---------------------------------------------------------------

def test_selftest_suite_all_detected_no_fp():
    suite = run_suite()
    assert suite["missed"] == [], suite["missed"]
    assert suite["false_positives"] == [], suite["false_positives"]
    assert suite["detection_rate"] == 1.0
    assert suite["total"] >= 50
    # honesty label
    assert "not an authoritative benchmark" in suite["note"]


# --- cli sast subcommand smoke ------------------------------------------------------

def test_cli_sast_subcommand(tmp_path):
    (tmp_path / "bad.py").write_text("os.system('ls ' + d)\n", encoding="utf-8")
    r = subprocess.run([PY, str(REPO / "cli.py"), "sast", str(tmp_path),
                        "--no-semgrep", "--no-deps"],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 1
    d = json.loads(r.stdout)
    assert not d["passed"]
    assert d["fail_on"] == "high"
