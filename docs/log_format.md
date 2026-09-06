# Secure-Vibe Log Format

Logs are output as **JSON Lines** (one complete JSON record per line), written by default to
`logs/<YYYY-MM-DD>.jsonl` (one file per day). UTF-8 encoded, `ensure_ascii=False`.

Records fall into three event types (distinguished by the `event` field):

## 1. `generation` — one complete generation process

```json
{
  "timestamp": "2026-09-02T14:30:00.123",
  "event": "generation",
  "task_description": "Implement a user login API",
  "language": "python",
  "framework": "Flask",
  "context": "Needs to support JWT",
  "llm_backend": "MockBackend",
  "rounds": [
    {
      "round_no": 0,
      "action": "generate",
      "passed": false,
      "violations": [
        {
          "rule_id": "PY-001",
          "rule_name": "dangerous_eval_exec",
          "line": 5,
          "column": 4,
          "snippet": "result = eval(user_input)",
          "message": "Using eval/exec to execute code dynamically (code injection risk)",
          "severity": "high",
          "fix_hint": "Use json.loads for JSON; use ast.literal_eval for expression evaluation",
          "cwe": "CWE-95",
          "checker": "ast",
          "template": "safe_eval_alt"
        }
      ],
      "elapsed_ms": 1.234,
      "code": "<full code for this round, controlled by the log_code switch>"
    }
  ],
  "first_generation_code": "<full text of first generated code>",
  "total_retries": 2,
  "llm_calls": 3,
  "final_verdict": "passed",
  "final_code": "<full text of final delivered code>",
  "report": "",
  "total_elapsed_ms": 45.678,
  "manually_modified": false,
  "manual_diff": ""
}
```

### Field Description

| Field | Type | Description |
|------|------|------|
| `timestamp` | ISO 8601 | Record time (millisecond precision) |
| `event` | string | `generation` / `missed_pattern` / `rule_promoted` |
| `task_description` | string | User task description |
| `language` / `framework` / `context` | string | Generation context |
| `llm_backend` | string | Backend class name used (MockBackend/OpenAIBackend/...) |
| `rounds[]` | array | Details of each round: round number, action, validation result, violation list, elapsed time, code |
| `rounds[].action` | string | `generate` (first generation) / `deterministic_fix` (deterministic template replacement) / `llm_repair` (LLM repair) |
| `first_generation_code` | string | First generated code (controlled by the `log_code` switch; `<N chars>` when disabled) |
| `total_retries` | int | Number of repair retries (excluding the first generation) |
| `llm_calls` | int | Total number of LLM calls |
| `final_verdict` | string | `passed` / `failed` / `needs_human_review` (retry limit exceeded) |
| `final_code` | string | Final delivered code |
| `report` | string | Full vulnerability report on failure (Markdown) |
| `total_elapsed_ms` | float | Total elapsed time for the whole process |
| `manually_modified` | bool | Whether the user manually modified the generated code |
| `manual_diff` | string | Unified diff of manual modifications (produced by `compute_manual_diff()`) |

### Privacy Controls (config.yaml → logging)

- `mask_secrets: true`: automatically mask suspected secrets (`sk-...`, `AKIA...`, assignment strings) before writing logs.
- `log_code: false`: do not record full code, only the character count.
- `log_inputs: true`: whether to record the task description and context.

## 2. `missed_pattern` — new attack patterns that were missed/bypassed (material for the rule iteration loop)

```json
{
  "timestamp": "2026-09-02T15:00:00.000",
  "event": "missed_pattern",
  "pattern": "getattr(builtins, 'eval')(x)",
  "source_code": "<related code snippet>",
  "note": "Dynamic attribute call missed by the validator",
  "severity": "medium",
  "status": "pending_review"
}
```

After human review, write the new rule into `rules/*.yaml` and call `log_rule_promoted()` to record the promotion action.

## 3. `rule_promoted` — audit record of promoting a missed detection pattern to an official rule

```json
{
  "timestamp": "2026-09-02T16:00:00.000",
  "event": "rule_promoted",
  "rule_id": "PY-011",
  "rule_yaml": "<YAML definition of the new rule>",
  "note": "From the missed_pattern review on 2026-09-02"
}
```

## Analysis Usage

```bash
# Count daily generations and pass rate
python -c "
import json, collections
c = collections.Counter()
for line in open('logs/2026-09-02.jsonl', encoding='utf-8'):
    r = json.loads(line)
    if r['event'] == 'generation':
        c[r['final_verdict']] += 1
print(c)
"

# Find all records that need human repair
grep needs_human_review logs/*.jsonl

# Rule hit ranking (basis for iterating rules)
python -c "
import json, collections
c = collections.Counter()
for line in open('logs/2026-09-02.jsonl', encoding='utf-8'):
    r = json.loads(line)
    for rd in r.get('rounds', []):
        for v in rd['violations']:
            c[v['rule_id']] += 1
for k, n in c.most_common():
    print(f'{k}: {n}')
"
```
