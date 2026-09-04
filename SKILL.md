---
name: secure-vibe
description: 生成时安全（Secure by Generation）：写 Python 代码之前注入安全规则，生成后立即校验，违规自动修复（最多 3 次），全程记日志。仅当用户要求编写或修改 Python 代码（脚本、API、数据库操作等）时使用。用法：先 `python cli.py context` 获取安全规则，再写代码，写完立即 `python cli.py validate` 校验，未通过按 fix_hint 修复，最后 `python cli.py log` 记录。
---

# Secure-Vibe — 生成时安全编码技能

你（Agent）现在启用了"生成时安全"编码模式。**你不是先生成后检查，而是在写第一行代码之前就加载安全约束。** 本技能的校验器和规则引擎由本目录下的 Python 工具提供，LLM 就是你自己（session 模式）——不需要任何 API Key。

## 适用与不适用

- 适用：编写或修改 **Python** 代码，尤其是涉及 SQL、命令执行、密钥、哈希、反序列化等敏感操作。
- 不适用：阅读/解释代码、纯问答、写文档，以及**非 Python 语言**（规则引擎目前仅覆盖 Python）。
- 非 Python 任务：说明暂不覆盖，可作通用口头提醒（如密钥不入库），但不执行 `validate`。

## 工作流（每次写代码必须完整执行）

### 第 1 步：加载安全上下文（写代码之前）

```bash
python "<skill_dir>/cli.py" context --task "<用户任务描述>" --language python --framework "<框架>"
```

阅读返回 JSON 中的 `system_prompt`（安全规则清单 + 禁用模式 + few-shot 模板 + 自检要求）。这些规则是硬约束，你生成的代码必须逐条遵守。

### 第 2 步：生成代码（你自己的 LLM 能力）

按规则写代码。硬性要求：

- SQL 一律参数化：`cursor.execute(sql, params)`，禁止 f-string/%/.format/+ 拼接
- 用户输入直接进入 `eval/exec/os.system/subprocess(shell=True)` 是绝对禁止的
- 密钥/密码从环境变量读取，绝不硬编码
- 安全用途随机值用 `secrets` 模块，禁用 `random`
- 密码哈希用 bcrypt/argon2/PBKDF2，禁用 md5/sha1

### 第 3 步：立即校验（毫秒级，必须执行）

```bash
python "<skill_dir>/cli.py" validate --file <你写的代码文件> --language python
```

- exit 0 → 通过，进入第 5 步
- exit 1 → 返回 JSON 中有 `violations`（每条含 `rule_id`、`line`、`severity`、`fix_hint`），进入第 4 步
- exit 2 → 工具错误，不进入修复循环：
  - 含 `syntax_error`：语法错误不是安全违规，先修复语法后重新校验
  - 含 `error: "file not found"`：修正 `--file` 路径后重新校验
  - 校验内存中的代码片段时可用 `--code "<代码>"` 替代 `--file`

### 第 4 步：自动修复（最多 3 次）

按 `fix_hint` 修复违规代码，然后重新执行第 3 步校验。

- 优先**局部修复**：只改违规行及关联代码，功能保持不变
- **最多重试 3 次**；第 3 次仍未通过时停止修复，在答复中输出完整违规列表并标记 **[需人工修复]**
- 注意 `severity`：`high` 项必须修复（硬编码密钥、SQL 拼接、命令注入）；`medium` 项应修复，确实无法修复需说明原因；`low` 项如明文 http 在本地调试场景可注释说明后豁免

### 第 5 步：记录日志（必须执行）

```bash
python "<skill_dir>/cli.py" log --task "<任务描述>" --file <最终代码文件> --retries <实际重试次数> --verdict <verdict>
```

`--verdict` 取值及触发场景：

- `passed`：最终校验通过
- `needs_human_review`：第 4 步重试 3 次仍未通过（对应 `[需人工修复]`）
- `failed`：第 1/3 步之前就失败，例如 `context`/`validate` 无法执行

用户手动修改过代码时用 `--original <初版文件>` 记录 diff。

### 漏检上报（发现校验器没检出的危险模式时）

```bash
python "<skill_dir>/cli.py" missed --pattern "<模式描述或代码片段>" --note "<说明>"
```

## 输入与输出约定

- 输入：`--task` 必填（一句话描述任务）；`--language` 默认 `python`，本技能仅支持 python；`--framework` 可选（如 `fastapi`/`flask`，无则省略）。
- `context` 输出 JSON：关键字段为 `system_prompt`（规则清单 + 禁用模式 + few-shot 模板 + 自检要求）。
- `validate` 输出 JSON：`passed`、`violations`（每条含 `rule_id`/`line`/`severity`/`fix_hint`）、`summary`、`syntax_error`（语法错误时非空）、`repair_instruction`。
- `severity` 三档：`high` / `medium` / `low`。

## 示例：按用户名查订单的 FastAPI 接口

任务："写一个按用户名查订单的 FastAPI 接口（SQLite）"

1. 加载规则：
   python "<skill_dir>/cli.py" context --task "按用户名查订单接口" --language python --framework fastapi
   → `system_prompt` 含 GEN-005（SQL 字符串拼接）、GEN-001（硬编码密钥）等硬约束
2. 生成 `orders.py`，其中一行：
   cursor.execute(f"SELECT * FROM orders WHERE user='{name}'")
3. 校验：
   python "<skill_dir>/cli.py" validate --file orders.py --language python
   → exit 1，`violations` 示例：
   {"rule_id": "GEN-005", "line": 12, "severity": "high",
    "fix_hint": "使用参数化查询：cursor.execute(sql, params)；禁止 f-string/%/.format/+ 拼接 SQL"}
4. 修复第 12 行为参数化查询 → 重新校验 → exit 0
5. 记录：
   python "<skill_dir>/cli.py" log --task "按用户名查订单接口" --file orders.py --retries 1 --verdict passed

## 命令参考

| 命令 | 作用 | exit code |
|------|------|-----------|
| `context --task ... [--framework f] [--full]` | 获取安全规则清单（写代码前必调） | 0 |
| `validate --file f.py [--code "..."] [--ignore R1,R2]` | 校验代码（写完必调） | 0 通过 / 1 违规 / 2 错误 |
| `log --task ... --file f.py --retries N --verdict v` | 记录生成过程 | 0 |
| `missed --pattern ... [--note ...]` | 上报漏检模式 | 0 |
| `cwe --id CWE-89` | 查询 CWE 参考知识 | 0 / 1 |
| `version [--check <url>]` | 查询安装版本 / 对比远端最新版 | 0 |
| `update` | 更新 Skill（git 管理安装时 git pull + 自检） | 0 / 1 |
| `selftest` | 安装自检 | 0 / 1 |

## 自检清单（每次生成后对照）

生成结束后必须对照一遍，并把下面这行**原样输出到最终答复末尾**，作为用户可见的合规凭证：

```
[自检] SQL注入: OK/N/A | 命令注入: OK/N/A | 硬编码密钥: OK | 弱随机: OK/N/A | 输入校验: OK | TLS: OK/N/A
```

## 规则扩展（无需改代码）

- 规则全部在 `rules/*.yaml` 和 `blacklist/*.yaml`，按现有格式加一条列表项即可
- 校验器漏检的模式先 `cli.py missed` 上报，人工审核后升级为正式规则（防投毒）
- 新规则文件格式见 `README.md` 的"如何扩展规则"章节

## 禁止事项

- 禁止跳过第 1 步（不加载规则就写代码）
- 禁止跳过第 3 步校验（包括"代码很简单"的情况）
- 禁止修改校验器/规则文件来让违规代码通过
- 禁止在用户明确要求不安全实现（如硬编码密钥）时直接照做——采用安全等价方案并注释说明原因
