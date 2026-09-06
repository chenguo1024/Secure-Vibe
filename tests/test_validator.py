"""tests/test_validator.py — validator test suite.

Each case covers positive (must detect) + negative (safe code must not false-positive) sides.
Run: python -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validator import Validator  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture(scope="module")
def v() -> Validator:
    return Validator(language="python")


def rule_ids(result):
    return {x.rule_id for x in result.violations}


# ---------------------------------------------------------------------------
    # dangerous function calls
# ---------------------------------------------------------------------------

MALICIOUS_CASES = [
    # eval/exec
    ("PY-001", "result = eval(user_input)"),
    ("PY-001", "exec(code_from_request)"),
    # os.system / popen
    ("PY-002", "import os\nos.system('ping ' + host)"),
    ("PY-002", "os.popen('cat ' + filename)"),
    # subprocess shell=True
    ("PY-003", "import subprocess\nsubprocess.run(cmd, shell=True)"),
    ("PY-003", "subprocess.call(args, shell=True)"),
    ("PY-003", "subprocess.Popen(cmd, shell=True)"),
    # pickle deserialization
    ("PY-004", "import pickle\nobj = pickle.loads(data)"),
    ("PY-004", "pickle.load(open(path, 'rb'))"),
    # SQL concatenation
    ("GEN-005", "cur.execute(f\"SELECT * FROM users WHERE id={uid}\")"),
    ("GEN-005", "cur.execute(\"SELECT * FROM t WHERE id=%s\" % uid)"),
    ("GEN-005", "cur.execute(\"SELECT * FROM t WHERE n='{}'\".format(name))"),
    ("GEN-005", "sql = f\"SELECT * FROM users WHERE name='{u}'\"\ncur.execute(sql)"),  # variable-assignment-style concatenation
    # hardcoded secrets
    ("GEN-001", "API_KEY = \"sk-1234567890abcdef1234\""),
    ("GEN-001", "password = \"SuperSecret123\""),
    ("GEN-001", "aws_key = \"AKIAIOSFODNN7EXAMPLE\""),
    ("GEN-001", 'db_uri = "mysql://root:P@ssw0rd@localhost/db"'),
    # plaintext HTTP
    ("GEN-002", "resp = requests.get(\"http://api.example.com/data\")"),
    # insecure randomness
    ("GEN-003", "import random\ntoken = random.randint(100000, 999999)"),
    ("GEN-003", "random.choice(user_list)"),
    # weak hashes
    ("GEN-004", "import hashlib\nhashlib.md5(data)"),
    ("GEN-004", "digest = hashlib.sha1(payload)"),
    # JWT / TLS
    ("GEN-007", "jwt.decode(token, options={'verify_signature': False})"),
    ("GEN-008", "requests.post(url, verify=False)"),
    ("GEN-008", "ctx = ssl._create_unverified_context()"),
    # sensitive info in prints
    ("GEN-006", "print(\"password:\", user_password)"),
    # yaml.load without a Loader
    ("PY-005", "import yaml\ncfg = yaml.load(f)"),
    # Flask debug
    ("PY-008", "app.run(debug=True)"),
    # input directly into a dangerous function
    ("PY-010", "eval(input())"),
    # dynamic access to dangerous builtins (static-analysis bypass, from the missed-detection loop)
    ("BL-005", 'getattr(builtins, "eval")(x)'),
    ("BL-005", 'getattr(__builtins__, "exec")(code)'),
    ("BL-005", '__builtins__["open"]("/etc/passwd")'),
]

SAFE_CASES = [
    # parameterized SQL
    "cur.execute(\"SELECT * FROM users WHERE id=?\", (uid,))",
    "cur.execute(\"SELECT * FROM users WHERE id=%s\", [uid])",
    # secrets safe randomness
    "import secrets\ntoken = secrets.token_urlsafe(32)",
    # strong hash
    "import hashlib\nhashlib.sha256(data).hexdigest()",
    "hashlib.pbkdf2_hmac('sha256', pwd, salt, 600000)",
    # secrets from env vars
    "api_key = os.environ.get('API_KEY')",
    "password = config['password']",
    # https
    "resp = requests.get('https://api.example.com/data')",
        "resp = requests.get('http://localhost:8080/debug')  # local debugging",
    # subprocess shell=False
    "subprocess.run(['ls', '-l'], shell=False)",
    "subprocess.run(['ls', '-l'])",
    # safe eval alternative
    "import ast\nvalue = ast.literal_eval(expr)",
    "import json\nobj = json.loads(text)",
    # yaml safe_load
    "import yaml\ncfg = yaml.safe_load(f)",
    "cfg = yaml.load(f, Loader=yaml.SafeLoader)",
    # correct JWT verification
    "payload = jwt.decode(token, key, algorithms=['HS256'])",
    # default TLS verification (a literal fixed URL must not trip the SSRF rule)
    "requests.get(\"https://api.example.com/health\")",
    # Flask debug controlled via env var
    "app.run(debug=os.environ.get('FLASK_DEBUG') == '1')",
    # suspicious words inside comments/strings must not false-positive
    "# use secrets instead of the random module",
    "docstring = 'we use eval-free approach'",
    # placeholders do not count as hardcoded secrets
    'API_KEY = "YOUR_API_KEY_HERE"',
    'password = os.getenv("DB_PASSWORD")',
    # pickle on trusted internal data without network trace (still flagged, but not BL-004)
]


@pytest.mark.parametrize("rule_id,code", MALICIOUS_CASES, ids=[c[0] for c in MALICIOUS_CASES])
def test_detects_violations(v: Validator, rule_id: str, code: str):
    result = v.validate(code)
    assert not result.passed, f"should detect a violation but passed: {code!r}\n{result.summary()}"
    assert rule_id in rule_ids(result), (
            f"expected {rule_id}, got {rule_ids(result)}\n{result.summary()}"
    )


@pytest.mark.parametrize("code", SAFE_CASES)
def test_safe_code_passes(v: Validator, code: str):
    result = v.validate(code)
    assert result.passed, f"safe code false-positived:\n{code!r}\n{result.summary()}"


# ---------------------------------------------------------------------------
    # behavioral details
# ---------------------------------------------------------------------------

def test_violation_has_location_and_hint(v: Validator):
    result = v.validate("os.system('ls ' + arg)")
    assert not result.passed
    viol = result.violations[0]
    assert viol.line >= 1
    assert viol.rule_id
    assert viol.fix_hint
    assert viol.snippet


def test_severity_levels(v: Validator):
    result = v.validate("eval(x)\ntoken = random.randint(1, 9)")
    severities = {v_.rule_id: v_.severity for v_ in result.violations}
    assert severities.get("PY-001") == "high"
    assert severities.get("GEN-003") == "medium"


def test_syntax_error_code_still_checked_by_regex(v: Validator):
    # the regex engine must still work when AST parsing fails (code-fragment scenarios)
    result = v.validate("def broken(:\n    os.system(cmd")
    assert not result.passed
    assert "PY-002" in rule_ids(result)
    assert result.error  # the syntax error is recorded


def test_validation_is_fast(v: Validator):
    import time
    big_code = "\n".join(
        f"def f{i}(x):\n    return x + {i}" for i in range(500)
    )
    t0 = time.perf_counter()
    v.validate(big_code)
    elapsed = (time.perf_counter() - t0) * 1000
    # 500 lines of plain safe functions; the 400ms bound tolerates load variance on CI/desktops
    # (measured 150-260ms jitter locally; the old 200ms bound was flaky)
    assert elapsed < 400, f"validating 500 lines took {elapsed:.0f}ms, over budget"


def test_custom_ignore_rules():
    v = Validator(language="python", ignore_rules=["PY-001"])
    result = v.validate("eval(user_input)")
    assert result.passed or "PY-001" not in rule_ids(result)


def test_summary_format(v: Validator):
    result = v.validate("eval(x)")
    s = result.summary()
    assert s.startswith("FAIL")
    assert "PY-001" in s
    assert "fix" in s
