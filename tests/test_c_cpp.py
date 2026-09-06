"""tests/test_c_cpp.py — C/C++ multi-language rule tests."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.context_builder import build_prompts, load_rules_for_prompt  # noqa: E402
from core.validator import Validator, language_chain, normalize_language  # noqa: E402


def validate_c(code: str):
    v = Validator("c")
    return v.validate(code)


def validate_cpp(code: str):
    v = Validator("cpp")
    return v.validate(code)


def ids(result):
    return {x.rule_id for x in result.violations}


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# language normalization & inheritance chains
# ---------------------------------------------------------------------------

def test_language_normalization():
    assert normalize_language("C++") == "cpp"
    assert normalize_language("c++") == "cpp"
    assert normalize_language("cxx") == "cpp"
    assert normalize_language("py") == "python"
    assert normalize_language("Python") == "python"


def test_language_chain():
    assert language_chain("c") == ["general", "c"]
    assert language_chain("cpp") == ["general", "c", "cpp"]
    assert language_chain("python") == ["general", "python"]


def test_cpp_inherits_c_rules():
    v = Validator("cpp")
    rule_ids = {r.id for r in v.rules}
    assert "C-002" in rule_ids  # C rules inherit into C++
    assert "CPP-001" in rule_ids
    assert "GEN-001" in rule_ids  # general rules
    # blacklists inherit too
    assert "BLC-001" in rule_ids


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# C malicious cases
# ---------------------------------------------------------------------------

def test_c_detects_system_and_blacklist():
    code = 'int main(char *cmd) { system(cmd); return 0; }'
    r = validate_c(code)
    assert not r.passed
    got = ids(r)
    assert "C-001" in got       # system command execution
    assert "BLC-002" in got     # system with a variable argument (blacklist)


def test_c_detects_sprintf_strcpy():
    code = 'void f(const char *s) { char b[10]; strcpy(b, s); sprintf(b, "%s", s); }'
    r = validate_c(code)
    got = ids(r)
    assert "C-002" in got
    assert "C-003" in got


def test_c_detects_gets_blacklist():
    code = 'void f(void) { char b[10]; gets(b); }'
    r = validate_c(code)
    assert "BLC-001" in ids(r)


def test_c_detects_rand_for_security():
    code = 'unsigned int make_token(void) { return rand(); }'
    r = validate_c(code)
    assert "C-004" in ids(r)


def test_c_detects_nonconstant_format_string():
    code = 'void f(char *u) { printf(u); fprintf(stderr, u); }'
    r = validate_c(code)
    assert "C-005" in ids(r)


def test_c_detects_scanf_unbounded():
    code = 'void f(void) { char b[32]; scanf("%s", b); }'
    r = validate_c(code)
    assert "C-006" in ids(r)


def test_c_detects_insecure_tempfile():
    code = 'void f(void) { char *p = tmpnam(NULL); }'
    r = validate_c(code)
    assert "C-007" in ids(r)


def test_c_detects_weak_hash_via_general():
    # the GEN-004 (general) regex engine also works for C
    code = 'unsigned char *h(const char *d, unsigned long n) { return MD5(d, n, 0); }'
    r = validate_c(code)
    assert "GEN-004" in ids(r)


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# C++ malicious cases
# ---------------------------------------------------------------------------

def test_cpp_detects_std_unsafe_funcs():
    code = 'void f(const char *s) { char b[10]; std::strcpy(b, s); }'
    r = validate_cpp(code)
    assert "CPP-001" in ids(r)


def test_cpp_detects_system_concat():
    code = 'void f(std::string u) { system(("rm " + u).c_str()); }'
    r = validate_cpp(code)
    got = ids(r)
    assert "CPP-002" in got
    assert "C-001" in got  # the inherited C rule also fires


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# safe code - zero false positives
# ---------------------------------------------------------------------------

def test_c_safe_code_passes():
    code = (
        '#include <stdio.h>\n'
        '#include <string.h>\n'
        'int main(void) {\n'
        '    char buf[128];\n'
        '    snprintf(buf, sizeof(buf), "hello %d", 42);\n'
        '    strncpy(buf, "safe", sizeof(buf) - 1);\n'
        '    fgets(buf, sizeof(buf), stdin);\n'
        '    printf("%s\\n", buf);\n'
        '    int n = scanf("%63s", buf);\n'
        '    return n == 1 ? 0 : 1;\n'
        '}\n'
    )
    assert validate_c(code).passed


def test_c_no_syntax_error_reported():
    # C code is not Python: must not be reported as a syntax error by the Python parser
    code = 'int main(void) { printf("hi"); return 0; }'
    r = validate_c(code)
    assert r.error == ""


def test_cpp_safe_code_passes():
    code = (
        '#include <iostream>\n'
        '#include <string>\n'
        'int main() {\n'
        '    std::string name;\n'
        '    std::getline(std::cin, name);\n'
        '    std::cout << "hi " << name << "\\n";\n'
        '    return 0;\n'
        '}\n'
    )
    assert validate_cpp(code).passed


def test_c_safe_literal_system_passes():
    # compile-time constant command with a literal arg: BLC-002 must not fire
    code = 'int main(void) { system("date"); return 0; }'
    r = validate_c(code)
    assert "BLC-002" not in ids(r)


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# context building (multi-language)
# ---------------------------------------------------------------------------

def test_context_for_c_includes_c_rules():
    rules = load_rules_for_prompt("c")
    lang_ids = {r["id"] for r in rules["language_rules"]}
    assert "C-002" in lang_ids
    bl_ids = {r["id"] for r in rules["blacklist"]}
    assert "BLC-001" in bl_ids


def test_context_for_cpp_includes_c_and_cpp():
    rules = load_rules_for_prompt("cpp")
    lang_ids = {r["id"] for r in rules["language_rules"]}
    assert {"C-001", "CPP-001"} <= lang_ids


def test_prompts_cpp_uses_cpp_fewshot():
    system_prompt, _ = build_prompts("实现一个安全的文件读取工具", language="cpp")
    assert "CPP-001" in system_prompt
    assert "```cpp" in system_prompt  # C++ template injected as a cpp code block
    assert "safe_cpp_io" in system_prompt


def test_prompts_c_uses_c_fewshot():
    system_prompt, _ = build_prompts("实现一个安全的文件读取工具", language="c")
    assert "C-001" in system_prompt
    assert "```c" in system_prompt
