"""tests/test_web.py — PHP/HTML/JS web-development rule tests.
# secure-vibe: ignore-file - deliberate attack samples as test fixtures

Note: malicious sample strings are assembled at runtime (keeps full attack payloads off disk, avoiding AV quarantine).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.context_builder import build_prompts, load_rules_for_prompt  # noqa: E402
from core.validator import Validator, language_chain, normalize_language  # noqa: E402

# --- runtime-assembled payload fragments (full attack strings never hit the disk) ---
_PHP = "<?php "
_END = " ?>"
_EV = "e" + "val($_P" + "OST[\"code\"]); "
_SH = "sh" + "ell_exec($_" + "GET[\"cmd\"]); "
_SYS = "sys" + "tem($_" + "GET[\"cmd\"]); "
_UNSER = "un" + "serialize($_P" + "OST[\"data\"]); "
_INC = "in" + "clude($page . \".php\"); "
_SQL = ("$sql = \"SELECT * FROM users WHERE id=\" . $_G" + "ET[\"id\"]; "
        "mysqli_query($c, $sql); ")
_ECHO = "echo $_G" + "ET[\"name\"]; "
_EXTRACT = "ex" + "tract($_RE" + "QUEST); "
_JS_EV = "e" + "val(userInput);\nnew Fu" + "nction(userCode)();"


def validate(code: str, language: str):
    return Validator(language).validate(code)


def ids(result):
    return {x.rule_id for x in result.violations}


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# language normalization & inheritance chains
# ---------------------------------------------------------------------------

def test_language_normalization_web():
    assert normalize_language("JavaScript") == "js"
    assert normalize_language("htm") == "html"


def test_language_chain_web():
    assert language_chain("php") == ["general", "html", "js", "php"]
    assert language_chain("html") == ["general", "js", "html"]
    assert language_chain("js") == ["general", "js"]


def test_php_inherits_html_js_rules():
    v = Validator("php")
    rule_ids = {r.id for r in v.rules}
    assert {"PHP-001", "HTML-002", "JS-001", "GEN-001"} <= rule_ids
    assert {"BLP-001", "BLJ-001"} <= rule_ids  # blacklists inherit too


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# PHP malicious cases
# ---------------------------------------------------------------------------

def test_php_detects_shell_exec():
    r = validate(_PHP + _SH + _END, "php")
    assert {"PHP-001", "BLP-001"} <= ids(r)


def test_php_detects_system_via_blacklist():
    r = validate(_PHP + _SYS + _END, "php")
    assert "BLP-001" in ids(r)


def test_php_detects_eval():
    assert "PHP-002" in ids(validate(_PHP + _EV + _END, "php"))


def test_php_detects_sql_concat_superglobal():
    code = _PHP + _SQL + _END
    assert "PHP-003" in ids(validate(code, "php"))


def test_php_detects_unserialize_superglobal():
    assert "PHP-004" in ids(validate(_PHP + _UNSER + _END, "php"))


def test_php_detects_include_variable():
    # indirect case: assign first, then include (only PHP-005 fires)
    code = _PHP + "$page = $_G" + "ET[\"page\"]; " + _INC + _END
    r = validate(code, "php")
    assert "PHP-005" in ids(r)
    # direct case: superglobal straight into include (blacklist BLP-002)
    direct = _PHP + _INC.replace("$page", "$_G" + "ET[\"p\"]") + _END
    assert "BLP-002" in ids(validate(direct, "php"))


def test_php_detects_echo_superglobal_unescaped():
    assert "PHP-006" in ids(validate(_PHP + _ECHO + _END, "php"))


def test_php_detects_extract():
    assert "PHP-007" in ids(validate(_PHP + _EXTRACT + _END, "php"))


def test_php_detects_mixed_html_js_fragments():
    # mixed file: HTML/JS fragments in a PHP file are covered by the inherited rules
    code = (
        '<html><body>\n'
        '<a href="javascript:go()">x</a>\n'
        '<script>document.querySelector("#x").innerHTML = location.search;</script>\n'
        '<?php ' + _ECHO + ' ?>\n'
        '</body></html>\n'
    )
    r = validate(code, "php")
    assert {"HTML-002", "JS-002", "PHP-006", "BLJ-001"} <= ids(r)


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# JS malicious cases
# ---------------------------------------------------------------------------

def test_js_detects_eval_and_new_function():
    assert "JS-001" in ids(validate(_JS_EV, "js"))


def test_js_detects_innerhtml_nonliteral():
    assert "JS-002" in ids(validate('el.innerHTML = userText;', "js"))


def test_js_detects_dom_xss_from_location():
    assert {"JS-002", "BLJ-001"} <= ids(validate('el.innerHTML = location.hash;', "js"))


def test_js_detects_document_write():
    assert "JS-003" in ids(validate('document.write("<b>" + data + "</b>");', "js"))


def test_js_detects_string_timer():
    assert "JS-004" in ids(validate('setTimeout("doThing()", 100);', "js"))


def test_js_detects_postmessage_wildcard():
    assert "JS-005" in ids(validate('window.parent.postMessage(msg, "*");', "js"))


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# HTML malicious cases
# ---------------------------------------------------------------------------

def test_html_detects_javascript_url():
    assert "HTML-002" in ids(validate('<a href="javascript:steal()">x</a>', "html"))


def test_html_detects_inline_handler():
    assert "HTML-001" in ids(validate('<div onclick="doThing()">x</div>', "html"))


def test_html_detects_iframe_no_sandbox():
    assert "HTML-003" in ids(validate('<iframe src="https://evil.example.com"></iframe>', "html"))


def test_html_detects_cdn_script_no_sri():
    assert "HTML-004" in ids(validate('<script src="https://cdn.example.com/lib.js"></script>', "html"))


def test_html_detects_blank_no_noopener():
    assert "HTML-005" in ids(validate('<a href="https://x.com" target="_blank">外链</a>', "html"))


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# safe code, zero false positives
# ---------------------------------------------------------------------------

def test_php_safe_code_passes():
    code = (
        '<?php\n'
        '$name = $_GET["name"] ?? "";\n'
        'if ($name === "" || mb_strlen($name) > 64) { http_response_code(400); exit; }\n'
        '$stmt = $pdo->prepare("SELECT id FROM orders WHERE user = :u");\n'
        '$stmt->execute([":u" => $name]);\n'
        'echo htmlspecialchars((string)$name, ENT_QUOTES, "UTF-8");\n'
        '?>\n'
    )
    assert validate(code, "php").passed


def test_js_safe_code_passes():
    code = (
        'const out = document.querySelector("#out");\n'
        'out.textContent = "safe";\n'
        'el.addEventListener("click", () => { console.log("hi"); });\n'
        'window.parent.postMessage(msg, "https://app.example.com");\n'
    )
    assert validate(code, "js").passed


def test_html_safe_code_passes():
    code = (
        '<!DOCTYPE html>\n'
        '<html lang="zh-CN">\n'
        '<head><meta charset="utf-8"><title>ok</title></head>\n'
        '<body><p>hello</p>\n'
        '<iframe src="https://embed.example.com" sandbox="allow-scripts" title="w"></iframe>\n'
        '<a href="https://example.com" target="_blank" rel="noopener noreferrer">l</a>\n'
        '</body></html>\n'
    )
    assert validate(code, "html").passed


def test_js_no_syntax_error_reported():
    r = validate('const x = {a: 1}; console.log(x);', "js")
    assert r.error == ""


# ---------------------------------------------------------------------------
# --------------------------------------------------------------------------
# context building (multi-language)
# ---------------------------------------------------------------------------

def test_context_php_includes_inherited_rules():
    rules = load_rules_for_prompt("php")
    lang_ids = {r["id"] for r in rules["language_rules"]}
    assert {"PHP-001", "HTML-002", "JS-001"} <= lang_ids
    bl_ids = {r["id"] for r in rules["blacklist"]}
    assert "BLP-001" in bl_ids


def test_prompts_php_uses_php_fewshot():
    system_prompt, _ = build_prompts("实现一个安全的订单查询接口", language="php")
    assert "PHP-001" in system_prompt
    assert "```php" in system_prompt


def test_prompts_html_uses_html_fewshot():
    system_prompt, _ = build_prompts("写一个安全的产品展示页面", language="html")
    assert "HTML-002" in system_prompt
    assert "```html" in system_prompt


def test_prompts_js_uses_js_fewshot():
    system_prompt, _ = build_prompts("写一个安全的前端搜索组件", language="js")
    assert "JS-001" in system_prompt
    assert "```js" in system_prompt
