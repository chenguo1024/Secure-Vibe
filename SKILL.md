---
name: secure-vibe
description: Secure-by-generation guardrail for AI coding agents. Before writing code, inject security rules; after generating, validate in milliseconds and auto-repair up to 3 rounds, with full JSONL audit logging. Supports Python/C/C++/PHP/HTML/JS/Go/Java/Shell/Dockerfile/Kubernetes/Terraform/GitHub Actions. Use whenever the user asks to write or modify code, scripts, APIs, database operations, or container/infrastructure configs. Workflow: run `python cli.py context` first to load the rules, write the code, run `python cli.py validate` immediately after, fix per fix_hint, and finish with `python cli.py log`.
---

# Secure-Vibe — Secure-by-Generation Coding Skill

You (the agent) are now in secure-by-generation mode. **You do not generate first and inspect later — you load the security constraints before writing the first line of code.** The validator and rule engine in this directory are Python tools; the LLM is you (session mode) — no API key needed.

## Invocation (uniform across agents)

- The CLI is `cli.py`, located in **the directory that contains this SKILL.md** (referred to as `SKILL_DIR` below — the directory you read this file from). Invoke every command below with its absolute path, e.g. `python "$SKILL_DIR/cli.py"`. With `SKILL_DIR` expanded this works identically on opencode / Codex / Claude Code or any agent that can run a shell.
- If your working directory is already `SKILL_DIR`, `python cli.py ...` is equivalent (`cli.py` resolves rules/templates relative to its own location, not the cwd).
- Runtime requirement: Python 3.7+ (use `python3` on Linux/macOS when `python` is missing) with `pyyaml` installed (`requirements.txt`, i.e. `pip install pyyaml`). The install script finds a suitable interpreter and runs `selftest` automatically.
- `context` / `validate` / `log` / `selftest` are local, millisecond-scale, offline, zero API key.

## When to use / when not to use

- Supported languages: **Python / C / C++ / PHP / HTML / JavaScript(Node.js) / Go / Java / Shell / Dockerfile / Kubernetes / Terraform / GitHub Actions**.
- `--language` values: `python`, `c`, `cpp`, `php`, `html`, `js`, `go`, `sh`, `java`, `dockerfile`, `kubernetes`, `terraform`, `github-actions`. Aliases are accepted (`C++`→`cpp`, `javascript`/`node`/`nodejs`→`js`, `golang`→`go`, `bash`→`sh`, `docker`→`dockerfile`, `k8s`→`kubernetes`, `tf`→`terraform`, `workflow`/`gha`→`github-actions`).
- Coverage: the general rules (hardcoded secrets / SQL concat / plaintext HTTP / weak hashes / JWT / TLS) are shared by all languages; language-specific rules are listed below.
- Inheritance chains: `cpp` auto-loads C rules; `php` auto-loads HTML+JS rules (HTML/JS fragments inside PHP templates are also checked); `html` auto-loads JS rules (inline scripts are also checked).
- Not applicable: reading/explaining code, pure Q&A, writing docs, and **other languages** (Rust/Ruby/Swift etc. are not yet covered — the engine falls back to general rules only).
- For uncovered languages: state that a full rule set is not supported, give generic verbal cautions (e.g. no secrets in the repo), and do NOT call `validate` with a wrong `--language`.

### Language-specific detection capabilities

| Language | Specific rules (beyond the shared general rules) |
|----------|-------------------------------------------------|
| python | eval/exec, os.system, shell=True, pickle/yaml/marshal deserialization, input taint analysis (AST engine); SSRF, XXE, SSTI, path traversal, Zip Slip, NoSQL injection, ORM raw queries, JWT alg=none, CORS, open redirect, ReDoS, ML deserialization (torch/joblib/pandas) |
| c | system/popen, sprintf, strcpy/strcat, rand, non-constant format strings, scanf %s, tmpnam/mktemp |
| cpp | inherits all C rules + std:: unsafe functions, command built by string concatenation |
| php | shell_exec/eval/unserialize/include with variables, SQL concat with superglobals, unescaped echo of superglobals (XSS), extract; blacklist: superglobals into exec/include; inherits HTML+JS rules |
| html | inline event handlers, javascript: URLs, iframe without sandbox, CDN script without SRI, _blank without noopener; inherits JS rules |
| js | eval/new Function, non-literal innerHTML assignment (DOM XSS), document.write, string timers, postMessage wildcard origin; Node: child_process.exec concatenation, res.send reflection, prototype pollution, dynamic require; blacklist: URL sources into innerHTML, prototype pollution merge |
| go | commands via shell (exec.Command sh), SQL concat/fmt.Sprintf, SSRF, template.HTML, math/rand for security values, form values into file/command sinks, InsecureSkipVerify |
| java | Runtime.exec concat, JDBC Statement concat, ObjectInputStream deserialization, XXE (DocumentBuilder/SAXParser), java.util.Random, Spring Actuator sensitive endpoints, AES/ECB |
| sh | curl/wget piped to shell, eval of variables, rm -rf dangerous targets, unquoted variables, sudo NOPASSWD |
| dockerfile | USER root, ENV/ARG hardcoded secrets, curl\|sh, remote ADD, latest tag |
| kubernetes | privileged, hostPath, hostNetwork/hostPID, runAsUser 0/privilege escalation, full Secret exposure via env |
| terraform | 0.0.0.0/0 security groups, S3 public-read, public RDS, hardcoded secret defaults, all-ports ingress |
| github-actions | expanding ${{ github.event.* }} inside run (expression injection), echo secrets, @main/@master unpinned actions |

## Workflow (execute completely for every coding task)

### Step 1: Load security context (BEFORE writing code)

```bash
python "$SKILL_DIR/cli.py" context --task "<user task description>" --language <python|c|cpp|php|html|js|go|sh|java|dockerfile|kubernetes|terraform|github-actions> --framework "<framework>"
```

Read the `system_prompt` field of the returned JSON (rule list + banned patterns + few-shot templates + checklist requirement). These rules are hard constraints — every line of code you generate must comply.

### Step 2: Generate code (your own LLM ability)

Code per the rules. Hard requirements:

- SQL must be parameterized: `cursor.execute(sql, params)`; never f-string/%/.format/+ concatenation.
- User input must never flow directly into `eval/exec/os.system/subprocess(shell=True)`.
- Secrets/passwords come from environment variables; never hardcode.
- Security-sensitive randomness uses `secrets` (Python) / `crypto/rand` (Go) / `SecureRandom` (Java); never `random`/`math/rand`/`rand()`.
- Password hashing uses bcrypt/argon2/PBKDF2; never md5/sha1.

### Step 3: Validate immediately (millisecond-scale, mandatory)

```bash
python "$SKILL_DIR/cli.py" validate --file <your code file> --language <python|c|cpp|php|html|js|go|sh|java|dockerfile|kubernetes|terraform|github-actions>
```

- exit 0 → passed, go to Step 5
- exit 1 → JSON contains `violations` (each with `rule_id`, `line`, `severity`, `fix_hint`), go to Step 4
- exit 2 → tool error, do NOT enter the repair loop:
  - with `syntax_error`: syntax errors are not security violations; fix the syntax, then re-validate
  - with `error: "file not found"`: fix the `--file` path, then re-validate
  - to validate an in-memory snippet use `--code "<code>"` instead of `--file`

### Step 4: Auto-repair (max 3 rounds)

Fix the code per `fix_hint`, then re-run Step 3.

- Prefer **local fixes**: change only the violating lines and related code; keep behavior unchanged.
- **Max 3 retries.** If round 3 still fails, stop, output the full violation list and mark it **[needs human review]**.
- Respect `severity`: `high` must be fixed (hardcoded secrets, SQL concat, command injection); `medium` should be fixed, or explain explicitly why not; `low` (e.g. plaintext http for local debugging) may be exempted with an explanatory comment.

### Step 5: Log (mandatory)

```bash
python "$SKILL_DIR/cli.py" log --task "<task description>" --file <final code file> --retries <actual retry count> --verdict <verdict>
```

`--verdict` values and when to use them:

- `passed`: final validation passed
- `needs_human_review`: Step 4 retried 3 times and still failed (matches the `[needs human review]` mark)
- `failed`: the workflow failed before validation (e.g. `context`/`validate` could not run)

If the user manually modified the code, use `--original <first version file>` to record the diff.

### Missed-detection report (when you find a dangerous pattern the validator missed)

```bash
python "$SKILL_DIR/cli.py" missed --pattern "<pattern description or code snippet>" --note "<explanation>"
```

## Input/output contract

- Input: `--task` required (one-sentence task); `--language` one of the values above (default `python`); `--framework` optional (e.g. `fastapi`/`flask`/`laravel`/`spring`; omit when unused). For mixed templates (PHP files containing HTML/JS) pass `--language php` — the inheritance chain covers the HTML/JS fragments. For Docker/K8s/Terraform/GitHub Actions pass the IaC/pipeline language name directly.
- `context` output JSON: key field `system_prompt` (rule list + banned patterns + few-shot templates + checklist requirement).
- `validate` output JSON: `passed`, `violations` (each with `rule_id`/`line`/`severity`/`fix_hint`), `summary`, `syntax_error` (non-empty on syntax errors), `repair_instruction`.
- `severity` has three levels: `high` / `medium` / `low`.

## Example: FastAPI endpoint to query orders by username

Task: "Write a FastAPI endpoint that queries orders by username (SQLite)"

1. Load rules:
   python "$SKILL_DIR/cli.py" context --task "query orders by username endpoint" --language python --framework fastapi
   → `system_prompt` contains GEN-005 (SQL string concatenation), GEN-001 (hardcoded secrets), etc.
2. Generate `orders.py`, containing this line:
   cursor.execute(f"SELECT * FROM orders WHERE user='{name}'")
3. Validate:
   python "$SKILL_DIR/cli.py" validate --file orders.py --language python
   → exit 1, `violations` example:
   {"rule_id": "GEN-005", "line": 12, "severity": "high",
    "fix_hint": "Use parameterized query: cursor.execute(sql, params); never build SQL via f-string/%/.format/+ concatenation"}
4. Fix line 12 to a parameterized query → re-validate → exit 0
5. Log:
   python "$SKILL_DIR/cli.py" log --task "query orders by username endpoint" --file orders.py --retries 1 --verdict passed

## Command reference

| Command | Purpose | exit code |
|---------|---------|-----------|
| `context --task ... [--framework f] [--full]` | Get the security rule list (call before writing code) | 0 |
| `validate --file f.py [--code "..."] [--ignore R1,R2]` | Validate code (call after writing) | 0 pass / 1 violations / 2 error |
| `log --task ... --file f.py --retries N --verdict v` | Record the generation process | 0 |
| `missed --pattern ... [--note ...]` | Report a missed detection pattern | 0 |
| `cwe --id CWE-89` | Query CWE reference knowledge | 0 / 1 |
| `version [--check <url>]` | Show installed version / compare with remote latest | 0 |
| `update` | Update the skill (git pull + self-test on git-managed installs) | 0 / 1 |
| `selftest` | Install self-test | 0 / 1 |

## Self-check checklist (after every generation)

After generation you MUST review the checklist and output the following line **verbatim at the end of your final reply** as a user-visible compliance record:

```
[Self-check] SQL injection: OK/N/A | Command injection: OK/N/A | Hardcoded secrets: OK | Weak randomness: OK/N/A | Input validation: OK | TLS: OK/N/A
```
