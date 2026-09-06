"""core/selftest_suite.py — Zero-dependency positive/negative sample suite for cli.py selftest.
# secure-vibe: ignore-file - deliberate attack-sample strings as test data, not real secrets

~40 curated samples across all supported languages. Each sample is (language, code,
should_flag, note): `should_flag=True` samples must produce at least one violation,
`should_flag=False` samples must pass clean. This gives the post-install self-test a
measurable detection rate and false-positive rate — explicitly a *small self-test
suite* (自测小样本), not an authoritative benchmark (for that, run tools/run_evaluation
against SecurityEval when the dataset is available).
"""
from __future__ import annotations

# (language, code, should_flag, note)
SAMPLES: list[tuple[str, str, bool, str]] = [
    # --- python: must flag ---
    ("python", "x = eval(user_input)", True, "eval of untrusted input"),
    ("python", "exec(user_code)", True, "exec of untrusted input"),
    ("python", "os.system('ping ' + host)", True, "command injection"),
    ("python", "subprocess.run(cmd, shell=True)", True, "shell=True"),
    ("python", "API_KEY = 'sk-1234567890abcdefghij'", True, "hardcoded sk- key"),
    ("python", "password = 'hunter2hunter2'", True, "hardcoded password"),
    ("python", "conn.execute(f\"SELECT * FROM t WHERE id={uid}\")", True, "f-string SQL"),
    ("python", "cur.execute(\"SELECT * FROM t WHERE n='%s'\" % name)", True, "% SQL concat"),
    ("python", "requests.get(user_url)", True, "SSRF taint"),
    ("python", "yaml.load(data)", True, "unsafe yaml load"),
    ("python", "torch.load(model_path)", True, "ML pickle deserialization"),
    ("python", "pickle.loads(user_blob)", True, "pickle deserialization"),
    ("python", "jwt.decode(token, options={'verify_signature': False})", True, "JWT no verify"),
    ("python", "import hashlib\nh = hashlib.md5(pw).hexdigest()", True, "weak hash md5"),
    ("python", "token = random.randint(100000, 999999)", True, "weak randomness"),
    ("python", "open('/etc/' + user_path, 'r')", True, "path traversal taint"),
    ("python", "doc = collection.find({'$where': user_query})", True, "NoSQL operator injection"),
    ("python", "requests.post(url, verify=False)", True, "TLS verification disabled"),
    ("python", "from lxml import etree\ntree = etree.fromstring(xml_data)", True, "XXE parser"),
    ("python", "re.search(user_regex, user_input)", True, "ReDoS"),
    # --- python: must pass ---
    ("python", "import secrets\ntoken = secrets.token_urlsafe(32)", False, "CSPRNG"),
    ("python", "import json\ndata = json.loads(raw)", False, "safe parsing"),
    ("python", "import hashlib\nh = hashlib.sha256(data).hexdigest()", False, "strong hash"),
    ("python", "cursor.execute('SELECT * FROM t WHERE id=?', (uid,))", False, "parameterized SQL"),
    ("python", "import subprocess\nsubprocess.run(['ping', host], shell=False)", False, "no shell"),
    ("python", "def helper():\n    return os.environ.get('API_KEY')", False, "env config"),
    # --- js ---
    ("js", "eval(userInput);", True, "js eval"),
    ("js", "const { exec } = require('child_process');\nexec('ls ' + userDir);", True, "js command injection"),
    ("js", "window.parent.postMessage(msg, '*');", True, "postMessage wildcard"),
    ("js", "element.innerHTML = userInput;", True, "innerHTML XSS"),
    ("js", "const r = await fetch('/api/data');\nconst j = await r.json();", False, "safe fetch"),
    ("js", "document.getElementById('out').textContent = userInput;", False, "textContent safe"),
    # --- go ---
    ("go", "db.Query(\"SELECT * FROM t WHERE id=\" + id)", True, "go SQL concat"),
    ("go", "exec.Command(\"sh\", \"-c\", userInput)", True, "go shell injection"),
    ("go", "tlsConfig := &tls.Config{InsecureSkipVerify: true}", True, "go TLS skip verify"),
    ("go", "rows, err := db.Query(\"SELECT id, name FROM users WHERE id = ?\", uid)", False, "parameterized"),
    ("go", "hasher := sha256.New()\nhasher.Write(data)", False, "strong hash"),
    # --- sh ---
    ("sh", "curl -s https://example.com/install.sh | sh", True, "pipe to shell"),
    ("sh", "eval \"$USER_INPUT\"", True, "shell eval"),
    ("sh", "rm -rf \"$DIR\"/", True, "rm -rf variable"),
    ("sh", "set -euo pipefail\ngrep -r 'pattern' .", False, "safe shell"),
    # --- dockerfile ---
    ("dockerfile", "FROM alpine:3.20\nUSER root", True, "root user"),
    ("dockerfile", "FROM node:20\nRUN curl -s https://get.docker.com | sh", True, "pipe to shell in build"),
    ("dockerfile", "FROM python:3.12-slim\nUSER appuser\nCOPY . /app", False, "non-root"),
    # --- kubernetes ---
    ("kubernetes", "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: x\n    image: nginx\n    securityContext:\n      privileged: true", True, "privileged pod"),
    ("kubernetes", "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: x\n        image: nginx:1.27\n        securityContext:\n          runAsNonRoot: true", False, "non-root"),
    # --- terraform ---
    ("terraform", "resource \"aws_security_group\" \"x\" { ingress { cidr_blocks = [\"0.0.0.0/0\"] } }", True, "open ingress"),
    ("terraform", "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"my-bucket\"\n}", False, "plain bucket"),
    # --- github actions ---
    ("workflow", "run: echo \"title: ${{ github.event.issue.title }}\"", True, "workflow injection"),
    ("workflow", "run: make build", False, "static command"),
    # --- php / c ---
    ("php", "<?php echo $_GET['x']; ?>", True, "reflected XSS"),
    ("php", "<?php $cmd = $_POST['cmd']; system($cmd); ?>", True, "php command injection"),
    ("php", "<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); ?>", False, "escaped output"),
    ("c", "char buf[16];\nsprintf(buf, \"%s\", user);", True, "sprintf overflow"),
    ("c", "strcpy(dst, src);", True, "strcpy"),
    ("c", "strncpy(dst, src, sizeof(dst) - 1);", False, "bounded copy"),
]


def run_suite() -> dict:
    """Run the sample suite with the built-in Validator. Returns aggregate stats + failures."""
    from core.validator import Validator

    validators: dict[str, object] = {}
    detected = 0
    missed: list[dict] = []
    false_positives: list[dict] = []
    total_flag = sum(1 for s in SAMPLES if s[2])

    for language, code, should_flag, note in SAMPLES:
        v = validators.get(language)
        if v is None:
            from core.validator import Validator as _V
            v = _V(language=language)
            validators[language] = v
        result = v.validate(code)
        flagged = not result.passed
        if should_flag and flagged:
            detected += 1
        elif should_flag and not flagged:
            missed.append({"language": language, "note": note, "code": code[:60]})
        elif not should_flag and flagged:
            false_positives.append({
                "language": language, "note": note,
                "code": code[:60],
                "rules": [x.rule_id for x in result.violations][:4],
            })

    return {
        "total": len(SAMPLES),
        "should_flag": total_flag,
        "detected": detected,
        "missed": missed,
        "false_positives": false_positives,
        "detection_rate": round(detected / total_flag, 3) if total_flag else 1.0,
        "false_positive_count": len(false_positives),
        "note": "small self-test suite (自测小样本), not an authoritative benchmark; "
                "run tools/run_evaluation.py against SecurityEval for paper-grade numbers",
    }
