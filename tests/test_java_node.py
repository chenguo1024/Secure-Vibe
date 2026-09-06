"""tests/test_java_node.py — Java (Spring) and Node.js rule tests."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.context_builder import build_prompts  # noqa: E402
from core.validator import Validator, normalize_language  # noqa: E402


def validate(code: str, language: str):
    return Validator(language).validate(code)


def ids(result):
    return {x.rule_id for x in result.violations}


# --- language normalization ---

def test_language_normalization_node_java():
    assert normalize_language("nodejs") == "js"
    assert normalize_language("node") == "js"
    assert normalize_language("java") == "java"


# --- Java malicious cases ---

def test_java_detects_exec_concat():
    code = 'Runtime.getRuntime().exec("sh -c " + userInput);'
    assert "JAVA-001" in ids(validate(code, "java"))


def test_java_detects_jdbc_concat():
    code = 'stmt.executeQuery("SELECT * FROM t WHERE id=" + id);'
    assert "JAVA-002" in ids(validate(code, "java"))


def test_java_detects_deserialization():
    code = 'ObjectInputStream ois = new ObjectInputStream(input);'
    assert "JAVA-003" in ids(validate(code, "java"))


def test_java_detects_xxe():
    code = 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();'
    assert "JAVA-004" in ids(validate(code, "java"))


def test_java_detects_insecure_random():
    code = 'int token = new Random().nextInt(100000);'
    assert "JAVA-005" in ids(validate(code, "java"))


def test_java_detects_actuator():
    code = 'management.endpoints.web.exposure.include=env,beans,heapdump'
    assert "JAVA-006" in ids(validate(code, "java"))


def test_java_detects_ecb():
    code = 'Cipher.getInstance("AES/ECB/PKCS5Padding");'
    assert "JAVA-007" in ids(validate(code, "java"))


def test_java_safe_passes():
    code = (
        'import java.security.SecureRandom;\n'
        'SecureRandom rng = new SecureRandom();\n'
        'byte[] b = new byte[16];\n'
        'rng.nextBytes(b);\n'
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\n'
        'ps.setString(1, id);\n'
    )
    assert validate(code, "java").passed


def test_java_prepared_statement_not_flagged():
    r = validate('stmt.executeQuery("SELECT 1");', "java")
    assert "JAVA-002" not in ids(r)


# --- Node.js malicious cases ---

def test_node_detects_exec_string():
    code = 'exec("sh -c " + userInput);'
    assert "JS-006" in ids(validate(code, "js"))


def test_node_detects_res_send_xss():
    code = 'res.send(req.query.name);'
    assert "JS-007" in ids(validate(code, "js"))


def test_node_detects_prototype_pollution():
    code = 'merge({}, JSON.parse(req.body));'
    assert "BLJ-002" in ids(validate(code, "js"))


def test_node_detects_dynamic_require():
    code = 'require(userModule);'
    assert "JS-009" in ids(validate(code, "js"))


def test_node_safe_passes():
    code = (
        'const { execFile } = require("child_process");\n'
        'execFile("/sbin/ping", ["-c", "1", host]);\n'
        'res.status(200).json({ name: req.query.name });\n'
        'const path = require("path");\n'
    )
    assert validate(code, "js").passed


def test_node_inherited_by_html():
    # html inherits js rules: child_process.exec in an inline script must fire too
    code = '<script>exec("sh -c " + u);</script>'
    assert "JS-006" in ids(validate(code, "html"))


# --- context building ---

def test_prompts_java_uses_java_fewshot():
    system_prompt, _ = build_prompts("实现一个安全的订单查询服务", language="java")
    assert "JAVA-001" in system_prompt
    assert "```java" in system_prompt
