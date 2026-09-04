# Secure-Vibe — 生成时安全的代码生成 Skill

在 vibe-coding（AI 自由生成代码）场景中，**在代码生成过程中就引导模型写出安全代码**——
不是"先生成后检查"，而是：安全上下文注入 → 生成 → 毫秒级校验 → 自动修复循环。

## 两种使用模式

### 模式 A：安装进 Agent（推荐，Skill 的主形态）

把本 Skill 安装到 Agent（opencode / Claude Code / 任意支持技能目录的框架），
生成由 **Agent 自身的 LLM** 完成（session 模式），本 Skill 提供
上下文构建 / 毫秒级校验 / 修复指令 / 日志 四个确定性工具，**零 API 依赖、零密钥**。

```bash
# Windows（默认安装到 opencode 技能目录）
powershell -File install.ps1
# 或指定目标目录（Claude Code / 其他框架）
powershell -File install.ps1 -Target "$env:USERPROFILE\.claude\skills\secure-vibe"

# Linux / macOS
./install.sh                        # 默认 ~/.config/opencode/skill/secure-vibe
./install.sh ~/.claude/skills/secure-vibe
```

安装脚本自动复制技能文件并运行自检（`cli.py selftest`）。重启 Agent 后，
Agent 在写代码前会执行：

```
① cli.py context --task "..."      # 加载安全规则（写代码之前）
② （Agent 自身 LLM 生成代码）
③ cli.py validate --file f.py      # 毫秒级校验（exit 1 = 有违规 + fix_hint）
④ 按 fix_hint 修复，重试 ≤3 次；仍失败标记[需人工修复]
⑤ cli.py log --task "..." --file f.py --verdict passed   # 记录
```

## 版本化与自动更新（已安装用户如何拿到新版本）

三种更新路径，按发布方式选择：

### 路径 1：git 管理安装（推荐，一键更新）

```bash
# 安装时用 -Repo / 第二参数，目标目录由 git 管理
powershell -File install.ps1 -Target ~/.config/opencode/skill/secure-vibe -Repo https://github.com/yourname/secure-vibe.git
./install.sh ~/.config/opencode/skill/secure-vibe https://github.com/yourname/secure-vibe.git

# 你发布新版本后，用户一键更新（等价于 git pull --ff-only + 自检）
python ~/.config/opencode/skill/secure-vibe/cli.py update

# 查询当前版本 / 对比远端最新版
python cli.py version
python cli.py version --check https://github.com/yourname/secure-vibe
```

### 路径 2：重跑安装脚本（幂等，覆盖即更新）

`install.ps1` / `install.sh` 本身是幂等的——重跑即把新版文件覆盖到已安装目录：

```bash
powershell -File install.ps1      # 覆盖更新，不破坏 logs/（不在复制列表中）
```

`logs/` 和用户本地新增的规则不受影响（复制列表只含技能自身文件）。

### 路径 3：Agent 启动自检提示

SKILL.md 指示 Agent 在加载技能时可运行 `cli.py version` 上报版本，
用户据此决定是否更新。规则文件（`rules/*.yaml`）独立于代码版本，
用户本地新增的规则在 git 更新时若不冲突会自动保留（git merge 语义）。

### 版本规范

- `VERSION` 文件 + `config.yaml → version` 双写，发布新版本时同步递增
- `cli.py update` 输出 `version_before/version_after/updated`，便于用户确认

### 模式 B：独立函数库 / CLI / HTTP 服务

不装进 Agent 也能独立运行（此时 LLM 后端可配 openai/claude/ollama/mock）：

```bash
pip install pyyaml

python main.py --demo                              # 端到端演示（Mock，不联网）
python main.py --validate suspicious.py            # 校验已有代码
python main.py --task "实现用户登录接口"            # 独立生成
uvicorn server:app --port 8399                     # HTTP API
```

```python
from main import generate_secure_code, validate_code

# 独立生成（backend 按 config.yaml；session 模式注入 Agent 的 LLM）
outcome = generate_secure_code(
    task_description="实现用户登录接口",
    language="python", framework="Flask",
    session_fn=my_agent_llm_generate,   # 或 backend=已创建的后端
)
result = validate_code(code_string)     # 仅校验
```

## 架构

```
用户任务描述
     │
     ▼
① ContextBuilder  ── 读取 rules/*.yaml + templates/ → 拼装安全 System Prompt
     │                （角色设定 + 通用规则 + 语言规则 + 黑名单 + few-shot + 自检清单）
     ▼
② 生成 ───────────── Agent 自身 LLM（session 模式，推荐）/ OpenAI / Claude / Ollama / Mock
     │
     ▼
③ Validator  ──────── AST + 正则双引擎，毫秒级（<50ms），不依赖 Semgrep
     │
     ├─ 通过 ──► 交付代码 + JSONL 日志
     ▼ 不通过
④ RepairLoop  ─────── 混合策略:
     │                 高危项 → templates/ 确定性替换（零风险，不走 LLM）
     │                 低/中危 → LLM 局部重写（只改违规片段）
     │                 最多 3 轮，仍失败 → 漏洞报告 + 标记"需人工修复"
     ▼
⑤ SecureLogger  ───── JSONL 全程记录（输入/每轮代码/违规/重试/人工修改 diff）
```

### Agent 接入的三种方式（按集成深度递增）

| 方式 | 说明 | 适用 |
|------|------|------|
| **Shell 工具链**（install.ps1） | Agent 通过 Bash 工具调用 `cli.py` 的 context/validate/log/missed 子命令 | 任意 Agent 框架，零代码集成 |
| **Python session_fn** | 调用 `generate_secure_code(..., session_fn=agent_llm_generate)` 注入 Agent 的 LLM | Python 内嵌 |
| **MCP/LangChain 工具** | 把 cli.py 子命令包装为工具（见下方示例） | 框架原生工具集成 |

```python
# LangChain 工具示例
from langchain.tools import tool

@tool
def secure_validate(file_path: str) -> str:
    """校验代码安全性，返回违规列表与修复建议"""
    import subprocess, json
    r = subprocess.run(["python", "cli.py", "validate", "--file", file_path],
                       capture_output=True, text=True, encoding="utf-8")
    return json.dumps({"exit": r.returncode, **json.loads(r.stdout)}, ensure_ascii=False)
```

## 项目结构

```
Secure-Vibe/
├── SKILL.md                   # 技能定义（Agent 安装后读取的工作流指令）
├── install.ps1 / install.sh   # 安装到 Agent 技能目录（含自检）
├── cli.py                     # Agent 工具链桥（context/validate/log/missed/cwe/selftest）
├── main.py                    # 独立模式入口：generate_secure_code() / CLI
├── server.py                  # HTTP API（可选）
├── config.yaml                # LLM 后端 / 校验 / 修复 / 日志 / 评测配置
├── core/
│   ├── context_builder.py     # ① 安全上下文构建器
│   ├── llm_backend.py         # ② LLM 可插拔后端（session=Agent 自身模型）
│   ├── validator.py           # ③ AST+正则实时校验器
│   ├── ast_fixer.py           # ④a AST 确定性修复引擎（零 LLM，安全等价改写）
│   ├── repair_loop.py         # ④b 混合修复循环
│   └── logger.py              # ⑤ JSONL 日志
├── rules/
│   ├── general.yaml           # 通用规则（8 条：密钥/SQL拼接/弱随机/弱哈希/TLS/JWT...）
│   ├── python.yaml            # Python 规则（10 条：eval/os.system/shell=True/pickle...）
│   └── cwe_reference.yaml     # CWE 参考知识库（21 条，可由 tools/mine_cwe_rules.py 扩充）
├── blacklist/python.yaml      # 硬禁用黑名单（4 条）
├── templates/python/          # 安全模板（5 个）
│   ├── db_query.py            #    参数化 SQL
│   ├── password_hash.py       #    PBKDF2 密码哈希
│   ├── secure_token.py        #    secrets 安全 token
│   ├── auth.py                #    安全登录接口
│   └── file_upload.py         #    安全文件上传
├── tools/
│   ├── mine_cwe_rules.py      # 从 GHSA-CySec 等数据集挖掘 CWE→修复映射
│   ├── run_evaluation.py      # 专业级评测（SecurityEval，可选）
│   └── agent_e2e_check.py     # Agent 工具链端到端自检
├── tests/                     # 70 个用例（恶意检出 + 安全零误报 + 循环行为）
├── docs/
│   ├── log_format.md          # 日志格式规范
│   └── evaluation.md          # 专业级评测指南
└── logs/                      # JSONL 输出
```

## 如何扩展规则（无需改动代码）

在 `rules/python.yaml`（或 `general.yaml`）中新增一个列表项即可：

```yaml
- id: PY-011                       # 唯一 ID
  name: my_new_rule
  severity: high                   # high / medium / low
  cwe: CWE-XXX                     # 可选
  message: 人读说明
  fix_hint: 修复建议（会反馈给 LLM）
  template: db_query               # 可选，高危项对应的确定性替换模板
  match:                           # 匹配方式（可组合）
    ast_calls:                     # AST 危险调用（点路径）
      - dangerous.func
    ast_kwargs:                    # AST 参数约束
      subprocess.call: {shell: literal-true}
    regex:                         # 正则（按行匹配）
      - (?i)dangerous_pattern
    regex_flags: "i"               # 可选
    exclude_regex:                 # 排除模式（误报豁免）
      - safe_call
```

两种匹配引擎：

- **AST 引擎**（代码可解析时）：`ast_calls` 精确匹配调用点路径（支持 `from x import y`）；
  `ast_kwargs` 匹配关键字参数（如 `shell=True`）。
- **正则引擎**（始终执行，容忍片段代码）：按行匹配，自动跳过注释行，支持 `exclude_regex` 豁免。

规则 ID 加入 `config.yaml → validator.ignore_rules` 可全局放行。

## 如何扩展模板（few-shot）

在 `templates/python/` 下新增 `my_template.py`，并在 `core/context_builder.py` 的
`TASK_TEMPLATE_HINTS` 中加一行关键词映射，相关任务就会自动带上该 few-shot 示例：

```python
TASK_TEMPLATE_HINTS.append(("加密|encrypt|aes", "my_template"))
```

## 如何迭代（持续优化，无需训练模型）

1. **规则沉淀闭环**：日志中的人工修改 diff / 漏检模式 → `cli.py missed` 上报或
   `POST /feedback` → 人工审核 → 写入 `rules/*.yaml`（git 版本化）。
2. **数据集挖掘**：`python tools/mine_cwe_rules.py <GHSA-CySec 数据集>` 自动挖掘
   CWE→修复措施，补充 `rules/cwe_reference.yaml`（见 docs/evaluation.md）。
3. **命中统计**：按 `docs/log_format.md` 的分析脚本统计规则命中率，低价值规则降级，新攻击升级。
4. **专业级评测**：接入 SecurityEval 数据集后运行 `tools/run_evaluation.py`，
   按 `missed_by_cwe` 补规则，重跑验证提升。
5. 保留人工审核闸口（防规则投毒）。

## 运行测试

```bash
pip install pytest
python -m pytest tests/ -q          # 单元 + 集成（含 AST 确定性修复）
python cli.py selftest              # Agent 工具链自检
python tools/agent_e2e_check.py     # Agent 工具链端到端
python tools/server_smoke.py        # HTTP 服务冒烟测试（需 fastapi+uvicorn）
```

## 确定性修复（零 LLM 的安全等价改写）

高危违规优先由 `core/ast_fixer.py` 做 AST 节点级改写，不走 LLM（毫秒级、零风险）：

| 违规 | 确定性改写 |
|------|-----------|
| `insecure_random` | `random.randint(a,b)` → `secrets.randbelow(b-a+1)+a`；`choice` → `secrets.choice`；`getrandbits` → `secrets.randbits` |
| `weak_hash` | `hashlib.md5/sha1` → `hashlib.sha256` |
| `unsafe_yaml_load` | `yaml.load(...)` → `yaml.safe_load(...)`（丢弃 `Loader=` 参数） |
| `hardcoded_secret` | `NAME = "明文"` → `NAME = os.environ.get("NAME", "")`（自动补 `import os`） |

改写后自动补缺失 import（docstring 之后插入）、`ast.unparse` 还原源码、再校验复验，
全部在 `deterministic_fix()` 内完成。**无法证明安全等价的违规**（eval/shell=True 命令拆分/
pickle 反序列化）保留原样交给 LLM 或人工修复。

扩展新改写：在 `core/ast_fixer.py` 的 `_SecureTransformer` 中新增 `visit_*` 方法即可，
规则引擎与修复逻辑仍互不侵入。

## 检测项覆盖

| 类别 | 检测项 | 规则 ID |
|------|--------|---------|
| 危险函数 | eval/exec/compile | PY-001 |
| 命令注入 | os.system/os.popen、subprocess shell=True | PY-002/003 |
| SQL 注入 | 字符串拼接/格式化 SQL | GEN-005 |
| 反序列化 | pickle/yaml.load/marshal | PY-004/005/007 |
| 硬编码密钥 | API key/密码/私钥/云密钥 | GEN-001 |
| 明文传输 | http:// 明文链接 | GEN-002 |
| 弱随机 | random 模块生成安全值 | GEN-003 |
| 弱哈希 | md5/sha1 | GEN-004 |
| TLS | verify=False | GEN-008 |
| JWT | 签名校验关闭 | GEN-007 |
| 信息泄露 | 敏感信息打印/日志 | GEN-006 |
| 调试接口 | Flask debug=True、Django DEBUG | PY-008/009 |
| XSS | Markup/|safe | BL-003 |
| 输入链 | input/request 直连危险函数 | PY-010 |
