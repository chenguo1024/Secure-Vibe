"""临时脚本：模拟 Agent 通过 shell 调用 cli.py 的完整工具链流程。"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
py = sys.executable
tmp = os.environ["TEMP"] + os.sep

# Agent 第2步: 生成代码（故意带漏洞）
v1 = tmp + "agent_v1.py"
open(v1, "w", encoding="utf-8").write(
    "import sqlite3\n"
    "import random\n"
    "API_KEY = 'sk-hardcoded-key-1234567890'\n"
    "\n"
    "def login(username, password):\n"
    "    conn = sqlite3.connect('app.db')\n"
    "    sql = f\"SELECT * FROM users WHERE name='{username}' AND pwd='{password}'\"\n"
    "    row = conn.execute(sql).fetchone()\n"
    "    token = random.randint(100000, 999999)\n"
    "    return token\n"
)

# Agent 第3步: 校验（expect exit 1）
r = subprocess.run([py, "cli.py", "validate", "--file", v1],
                   capture_output=True, text=True, encoding="utf-8")
d = json.loads(r.stdout)
print("第1次校验: exit=%d passed=%s violations=%d" % (r.returncode, d["passed"], len(d["violations"])))
for v in d["violations"]:
    print("  -", v["rule_id"], "line", v["line"], v["rule_name"], "[%s]" % v["severity"])

# Agent 第4步: 修复（模拟 Agent 按 fix_hint 修好）
v2 = tmp + "agent_v2.py"
open(v2, "w", encoding="utf-8").write(
    "import os\n"
    "import secrets\n"
    "import sqlite3\n"
    "\n"
    "def login(username, password):\n"
    "    conn = sqlite3.connect('app.db')\n"
    "    row = conn.execute('SELECT * FROM users WHERE name=? AND pwd=?', (username, password)).fetchone()\n"
    "    token = secrets.randbelow(900000) + 100000\n"
    "    return token\n"
)
r = subprocess.run([py, "cli.py", "validate", "--file", v2],
                   capture_output=True, text=True, encoding="utf-8")
d = json.loads(r.stdout)
print("修复后校验: exit=%d passed=%s" % (r.returncode, d["passed"]))

# Agent 第5步: 记录日志（含人工修改 diff）
r = subprocess.run([py, "cli.py", "log", "--task", "agent-e2e", "--file", v2,
                    "--original", v1, "--retries", "1", "--verdict", "passed"],
                   capture_output=True, text=True, encoding="utf-8")
d = json.loads(r.stdout)
print("日志:", d)

# 漏检上报
r = subprocess.run([py, "cli.py", "missed", "--pattern", 'getattr(builtins, "eval")(x)',
                    "--note", "e2e test"],
                   capture_output=True, text=True, encoding="utf-8")
d = json.loads(r.stdout)
print("漏检上报:", d["ok"])
print("AGENT E2E: ALL OK")
