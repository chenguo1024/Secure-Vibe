"""tests/test_strip.py — lexical stripping (comments/strings blanked) + literal-sensitive rules."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validator import Validator  # noqa: E402
from core.strip import strip_code  # noqa: E402


def ids(r):
    return {v.rule_id for v in r.violations}


# --- strip_code unit behavior -------------------------------------------------

def test_strip_python_keeps_code_shape():
    s = strip_code('x = eval(user_input)  # eval example\ndoc = """eval(y)"""\n', "python")
    assert s is not None
    assert "eval(user_input)" in s          # real code kept
    assert "eval(y)" not in s               # docstring content blanked
    assert '"' in s                         # outer delimiters kept
    assert "#" not in s                     # comment blanked


def test_strip_preserves_line_count():
    code = "a = 1\nb = 'secret text'\n# comment\nc = 3\n"
    s = strip_code(code, "python")
    assert len(s.splitlines()) == len(code.splitlines())
    assert s.splitlines()[3] == "c = 3"


def test_strip_js():
    s = strip_code('const u = "https://x"; // eval\nlet t = `eval(${x}`;\n', "js")
    assert s is not None
    assert "https://x" not in s and "//" not in s
    assert "const u =" in s and "let t =" in s


def test_strip_unsupported_language():
    assert strip_code('x = "y"', "go") is None
    assert strip_code('x = "y"', "dockerfile") is None


def test_strip_robust_on_fragments():
    # unterminated strings / partial code must not raise
    assert strip_code('x = ("unclosed', "python") is not None
    assert strip_code("eval(user_input)", "python") is not None
    assert strip_code("const s = 'unterminated", "js") is not None


# --- false-positive reductions -------------------------------------------------

def test_python_docstring_example_not_flagged():
    v = Validator(language="python")
    code = (
        'def helper():\n'
        '    """Example: x = eval(user_input) is dangerous - do not copy."""\n'
        '    return json.loads(data)\n'
    )
    r = v.validate(code)
    assert r.passed, r.summary()


def test_python_commented_out_code_not_flagged():
    v = Validator(language="python")
    code = "# old = os.system(cmd)  # removed\ntoken = secrets.token_urlsafe(32)\n"
    r = v.validate(code)
    assert r.passed, r.summary()


def test_python_inline_comment_not_flagged():
    v = Validator(language="python")
    code = "data = json.loads(raw)  # previously: eval(raw) - fixed\n"
    r = v.validate(code)
    assert r.passed, r.summary()


def test_js_comment_and_string_not_flagged():
    v = Validator(language="js")
    code = '// eval(userInput) - removed\nconst q = "eval in a string";\n'
    r = v.validate(code)
    assert r.passed, r.summary()


# --- real detections survive stripping ------------------------------------------

def test_real_python_detection_still_fires():
    v = Validator(language="python")
    r = v.validate("import os\nx = eval(user_input)\nt = requests.get(user_url)\n")
    assert not r.passed
    assert "PY-001" in ids(r) or "PY-011" in ids(r)


def test_literal_sensitive_secret_still_detected():
    v = Validator(language="python")
    r = v.validate('API_KEY = "sk-1234567890abcdef1234"\n')
    assert not r.passed
    assert "GEN-001" in ids(r)


def test_literal_sensitive_sql_fstring_still_detected():
    v = Validator(language="python")
    r = v.validate('sql = f"SELECT * FROM users WHERE name=\'{u}\'"\ncur.execute(sql)\n')
    assert not r.passed
    assert "GEN-005" in ids(r)


def test_line_numbers_preserved():
    v = Validator(language="python")
    code = "# a comment about eval\nx = 1\ny = eval(user_input)\n"
    r = v.validate(code)
    assert not r.passed
    hit = [v2 for v2 in r.violations if v2.rule_id == "PY-001"]
    assert hit and hit[0].line == 3
