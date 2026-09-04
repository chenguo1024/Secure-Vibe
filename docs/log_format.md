# Secure-Vibe 日志格式说明

日志输出为 **JSON Lines** 格式（每行一条完整 JSON 记录），默认写入 `logs/<YYYY-MM-DD>.jsonl`（按日期分文件）。UTF-8 编码，`ensure_ascii=False`。

记录分三类事件（`event` 字段区分）：

## 1. `generation` — 一次完整生成过程

```json
{
  "timestamp": "2026-09-02T14:30:00.123",
  "event": "generation",
  "task_description": "实现用户登录接口",
  "language": "python",
  "framework": "Flask",
  "context": "需要支持 JWT",
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
          "message": "使用 eval/exec 动态执行代码（代码注入风险）",
          "severity": "high",
          "fix_hint": "JSON 用 json.loads；表达式求值用 ast.literal_eval",
          "cwe": "CWE-95",
          "checker": "ast",
          "template": "safe_eval_alt"
        }
      ],
      "elapsed_ms": 1.234,
      "code": "<该轮完整代码，受 log_code 开关控制>"
    }
  ],
  "first_generation_code": "<首次生成代码全文>",
  "total_retries": 2,
  "llm_calls": 3,
  "final_verdict": "passed",
  "final_code": "<最终交付代码全文>",
  "report": "",
  "total_elapsed_ms": 45.678,
  "manually_modified": false,
  "manual_diff": ""
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `timestamp` | ISO 8601 | 记录时间（毫秒精度） |
| `event` | string | `generation` / `missed_pattern` / `rule_promoted` |
| `task_description` | string | 用户任务描述 |
| `language` / `framework` / `context` | string | 生成上下文 |
| `llm_backend` | string | 使用的后端类名（MockBackend/OpenAIBackend/...） |
| `rounds[]` | array | 每轮明细：轮号、动作、校验结果、违规列表、耗时、代码 |
| `rounds[].action` | string | `generate`（首生）/ `deterministic_fix`（模板确定性替换）/ `llm_repair`（LLM 修复） |
| `first_generation_code` | string | 首次生成代码（受 `log_code` 开关控制，关闭时为 `<N chars>`） |
| `total_retries` | int | 修复重试次数（不含首次生成） |
| `llm_calls` | int | LLM 总调用次数 |
| `final_verdict` | string | `passed` / `failed` / `needs_human_review`（重试超限） |
| `final_code` | string | 最终交付代码 |
| `report` | string | 失败时的完整漏洞报告（Markdown） |
| `total_elapsed_ms` | float | 全流程耗时 |
| `manually_modified` | bool | 用户是否手动修改了生成的代码 |
| `manual_diff` | string | 人工修改的 unified diff（`compute_manual_diff()` 生成） |

### 隐私控制（config.yaml → logging）

- `mask_secrets: true`：日志写入前对疑似密钥（`sk-...`、`AKIA...`、赋值字符串）自动打码。
- `log_code: false`：不记录代码全文，只记录字符数。
- `log_inputs: true`：是否记录任务描述与上下文。

## 2. `missed_pattern` — 漏检/被绕过的新攻击模式（规则迭代闭环素材）

```json
{
  "timestamp": "2026-09-02T15:00:00.000",
  "event": "missed_pattern",
  "pattern": "getattr(builtins, 'eval')(x)",
  "source_code": "<相关代码片段>",
  "note": "校验器漏检的动态属性调用",
  "severity": "medium",
  "status": "pending_review"
}
```

人工审核后将新规则写入 `rules/*.yaml` 并调用 `log_rule_promoted()` 记录升级动作。

## 3. `rule_promoted` — 漏检模式升级为正式规则的审核记录

```json
{
  "timestamp": "2026-09-02T16:00:00.000",
  "event": "rule_promoted",
  "rule_id": "PY-011",
  "rule_yaml": "<新规则的 YAML 定义>",
  "note": "来自 2026-09-02 的 missed_pattern 审核"
}
```

## 分析用法

```bash
# 统计每日生成量与通过率
python -c "
import json, collections
c = collections.Counter()
for line in open('logs/2026-09-02.jsonl', encoding='utf-8'):
    r = json.loads(line)
    if r['event'] == 'generation':
        c[r['final_verdict']] += 1
print(c)
"

# 找出所有需人工修复的记录
grep needs_human_review logs/*.jsonl

# 规则命中率排行（迭代规则的依据）
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
