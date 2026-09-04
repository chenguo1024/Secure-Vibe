"""tests/test_taint.py — 轻量污点追踪测试."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.taint import find_tainted_sinks  # noqa: E402
from core.validator import Validator  # noqa: E402


def rules_and_checkers(code):
    v = Validator("python")
    r = v.validate(code)
    rule_ids = {x.rule_id for x in r.violations}
    checkers = {x.rule_id: x.checker for x in r.violations}
    return r, rule_ids, checkers


def test_simple_command_injection_taint():
    code = "import os\ncmd = input('host: ')\nos.system(cmd)"
    r, rule_ids, checkers = rules_and_checkers(code)
    assert "PY-002" in rule_ids
    # 污点版规则应存在（不是只有浅层正则命中）
    assert any(v.checker == "taint" for v in r.violations)


def test_indirect_variable_flow():
    code = "import os\npayload = sys.argv[1]\ncmd = 'ping ' + payload\nos.popen(cmd)"
    r, _, _ = rules_and_checkers(code)
    chain = [v for v in r.violations if v.checker == "taint"]
    assert chain, "应确认污点链条"
    assert "sys.argv" in chain[0].message


def test_eval_taint():
    code = "from flask import request\nvalue = request.args.get('expr')\neval(value)"
    r, _, _ = rules_and_checkers(code)
    assert any(v.checker == "taint" and v.rule_id == "PY-001" for v in r.violations)


def test_subprocess_shell_true_taint():
    code = "import subprocess\nhost = input()\nsubprocess.run('ping ' + host, shell=True)"
    r, _, _ = rules_and_checkers(code)
    assert any(v.checker == "taint" and v.rule_id == "PY-003" for v in r.violations)


def test_pickle_taint():
    code = "import pickle\nimport socket\ndata = socket.recv(4096)\npickle.loads(data)"
    r, _, _ = rules_and_checkers(code)
    assert any(v.rule_id == "PY-004" for v in r.violations)


def test_no_taint_without_source():
    # 无用户输入来源 → 不应有 taint 版违规（但仍有浅层 os.system 命中）
    code = "import os\ncmd = 'ls -la'\nos.system(cmd)"
    r, _, checkers = rules_and_checkers(code)
    assert "PY-002" in checkers
    assert all(c != "taint" for c in checkers.values())


def test_safe_code_no_taint():
    code = "import subprocess\nsubprocess.run(['ping', host], shell=False)"
    r, _, _ = rules_and_checkers(code)
    assert not any(v.checker == "taint" for v in r.violations)


def test_taint_dedupes_shallow_match():
    # 同一行既命中浅层 Py-002 又命中污点 → 只保留污点版（不重复同规则同行）
    code = "import os\nhost = input()\nos.system(host)"
    r, _, _ = rules_and_checkers(code)
    py002 = [v for v in r.violations if v.rule_id == "PY-002"]
    assert len(py002) == 1
    assert py002[0].checker == "taint"


def test_sys_stdin_source():
    # sys.stdin.read() 也是污点源（回归：曾漏检）
    code = "import sys\nimport os\ndata = sys.stdin.read()\nos.system(data)"
    r, _, _ = rules_and_checkers(code)
    assert any(v.checker == "taint" and v.rule_id == "PY-002" for v in r.violations)
