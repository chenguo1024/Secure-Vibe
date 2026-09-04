"""tests/test_validator.py — 校验器测试集.

每个检测项覆盖 正向（应检出）+ 反向（安全代码不应误报）用例。
运行: python -m pytest tests/ -q
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
# 危险函数调用
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
    # pickle 反序列化
    ("PY-004", "import pickle\nobj = pickle.loads(data)"),
    ("PY-004", "pickle.load(open(path, 'rb'))"),
    # SQL 拼接
    ("GEN-005", "cur.execute(f\"SELECT * FROM users WHERE id={uid}\")"),
    ("GEN-005", "cur.execute(\"SELECT * FROM t WHERE id=%s\" % uid)"),
    ("GEN-005", "cur.execute(\"SELECT * FROM t WHERE n='{}'\".format(name))"),
    ("GEN-005", "sql = f\"SELECT * FROM users WHERE name='{u}'\"\ncur.execute(sql)"),  # 变量赋值式拼接
    # 硬编码密钥
    ("GEN-001", "API_KEY = \"sk-1234567890abcdef1234\""),
    ("GEN-001", "password = \"SuperSecret123\""),
    ("GEN-001", "aws_key = \"AKIAIOSFODNN7EXAMPLE\""),
    ("GEN-001", 'db_uri = "mysql://root:P@ssw0rd@localhost/db"'),
    # 明文 HTTP
    ("GEN-002", "resp = requests.get(\"http://api.example.com/data\")"),
    # 不安全随机
    ("GEN-003", "import random\ntoken = random.randint(100000, 999999)"),
    ("GEN-003", "random.choice(user_list)"),
    # 弱哈希
    ("GEN-004", "import hashlib\nhashlib.md5(data)"),
    ("GEN-004", "digest = hashlib.sha1(payload)"),
    # JWT / TLS
    ("GEN-007", "jwt.decode(token, options={'verify_signature': False})"),
    ("GEN-008", "requests.post(url, verify=False)"),
    ("GEN-008", "ctx = ssl._create_unverified_context()"),
    # 敏感信息打印
    ("GEN-006", "print(\"password:\", user_password)"),
    # yaml.load 未指定 Loader
    ("PY-005", "import yaml\ncfg = yaml.load(f)"),
    # Flask debug
    ("PY-008", "app.run(debug=True)"),
    # input 直连危险函数
    ("PY-010", "eval(input())"),
]

SAFE_CASES = [
    # 参数化 SQL
    "cur.execute(\"SELECT * FROM users WHERE id=?\", (uid,))",
    "cur.execute(\"SELECT * FROM users WHERE id=%s\", [uid])",
    # secrets 安全随机
    "import secrets\ntoken = secrets.token_urlsafe(32)",
    # 强哈希
    "import hashlib\nhashlib.sha256(data).hexdigest()",
    "hashlib.pbkdf2_hmac('sha256', pwd, salt, 600000)",
    # 环境变量密钥
    "api_key = os.environ.get('API_KEY')",
    "password = config['password']",
    # https
    "resp = requests.get('https://api.example.com/data')",
    "resp = requests.get('http://localhost:8080/debug')  # 本地调试",
    # subprocess shell=False
    "subprocess.run(['ls', '-l'], shell=False)",
    "subprocess.run(['ls', '-l'])",
    # eval 安全替代
    "import ast\nvalue = ast.literal_eval(expr)",
    "import json\nobj = json.loads(text)",
    # yaml safe_load
    "import yaml\ncfg = yaml.safe_load(f)",
    "cfg = yaml.load(f, Loader=yaml.SafeLoader)",
    # JWT 正确校验
    "payload = jwt.decode(token, key, algorithms=['HS256'])",
    # TLS 默认校验
    "requests.get(url)  # verify 默认 True",
    # Flask debug 环境变量控制
    "app.run(debug=os.environ.get('FLASK_DEBUG') == '1')",
    # 注释/字符串中的可疑词不误报
    "# 使用 secrets 而不是 random 模块",
    "docstring = 'we use eval-free approach'",
    # 占位符不算硬编码
    'API_KEY = "YOUR_API_KEY_HERE"',
    'password = os.getenv("DB_PASSWORD")',
    # pickle 用于可信内部数据但无网络输入痕迹（仍报但非 BL-004）
]


@pytest.mark.parametrize("rule_id,code", MALICIOUS_CASES, ids=[c[0] for c in MALICIOUS_CASES])
def test_detects_violations(v: Validator, rule_id: str, code: str):
    result = v.validate(code)
    assert not result.passed, f"应检出违规但通过: {code!r}\n{result.summary()}"
    assert rule_id in rule_ids(result), (
        f"应命中 {rule_id}，实际命中 {rule_ids(result)}\n{result.summary()}"
    )


@pytest.mark.parametrize("code", SAFE_CASES)
def test_safe_code_passes(v: Validator, code: str):
    result = v.validate(code)
    assert result.passed, f"安全代码被误报:\n{code!r}\n{result.summary()}"


# ---------------------------------------------------------------------------
# 行为细节
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
    # AST 解析失败时正则引擎仍应工作（片段代码场景）
    result = v.validate("def broken(:\n    os.system(cmd")
    assert not result.passed
    assert "PY-002" in rule_ids(result)
    assert result.error  # 记录了语法错误


def test_validation_is_fast(v: Validator):
    import time
    big_code = "\n".join(
        f"def f{i}(x):\n    return x + {i}" for i in range(500)
    )
    t0 = time.perf_counter()
    v.validate(big_code)
    elapsed = (time.perf_counter() - t0) * 1000
    assert elapsed < 200, f"校验 500 行代码耗时 {elapsed:.0f}ms，超出预期"


def test_custom_ignore_rules():
    v = Validator(language="python", ignore_rules=["PY-001"])
    result = v.validate("eval(user_input)")
    assert result.passed or "PY-001" not in rule_ids(result)


def test_summary_format(v: Validator):
    result = v.validate("eval(x)")
    s = result.summary()
    assert s.startswith("FAIL")
    assert "PY-001" in s
    assert "修复" in s
