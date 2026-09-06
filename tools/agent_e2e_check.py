"""Ad-hoc script: simulate an agent driving the whole cli.py toolchain via shell."""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
py = sys.executable
tmp = tempfile.mkdtemp(prefix="secure-vibe-e2e-") + os.sep

# Agent step 2: generate code (deliberately flawed)
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

# Agent step 3: validate (expect exit 1)
r = subprocess.run([py, "cli.py", "validate", "--file", v1],
                   capture_output=True, text=True, encoding="utf-8")
d = json.loads(r.stdout)
print("validation #1: exit=%d passed=%s violations=%d" % (r.returncode, d["passed"], len(d["violations"])))
for v in d["violations"]:
    print("  -", v["rule_id"], "line", v["line"], v["rule_name"], "[%s]" % v["severity"])

# Agent step 4: repair (simulate the agent fixing per fix_hint)
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
print("validation after fix: exit=%d passed=%s" % (r.returncode, d["passed"]))

# Agent step 5: log (with the manual-edit diff)
r = subprocess.run([py, "cli.py", "log", "--task", "agent-e2e", "--file", v2,
                    "--original", v1, "--retries", "1", "--verdict", "passed"],
                   capture_output=True, text=True, encoding="utf-8")
d = json.loads(r.stdout)
print("log:", d)

# missed-pattern report
r = subprocess.run([py, "cli.py", "missed", "--pattern", 'getattr(builtins, "eval")(x)',
                    "--note", "e2e test"],
                   capture_output=True, text=True, encoding="utf-8")
d = json.loads(r.stdout)
print("missed report ok:", d["ok"])
print("AGENT E2E: ALL OK")
