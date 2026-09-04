# Secure-Vibe SKILL.md 审查汇总

- 审查对象：`SKILL.md`（91 行）
- 审查时间：2026-09-04
- 结论：可用但不够严谨；综合评分 6/10
- 评分明细：目标清晰度 7 / 输入输出定义 5 / 可执行性 8 / 示例质量 2 / 边界与安全性 6 / 结构与可维护性 8

## 主要问题（按严重程度）

### 【高】1. 适用对象过度泛化，与校验器语言能力冲突
- frontmatter description 要求"写代码/脚本/实现功能/生成 API/接口/数据库操作时必须使用"，但 `rules/` 下只有 `python.yaml`、`general.yaml`，`--language` 默认 `python`。
- 对 JS/Java/Go 代码会用 Python 规则误判或漏判，却仍声称"必须使用"。

### 【高】2. validate 的 exit code 2 在工作流中被遗漏
- 第 3 步只区分 exit 0（通过）和 exit 1（违规）；命令表却写明 exit 2 = 错误。
- 实测 `cli.py:117/123`：文件不存在、缺 `--file/--code` 时返回 2；代码语法错误时 `syntax_error` 字段非空。
- Agent 遇到路径错误或语法错误时无指令可循，可能卡死或误判为违规。

### 【中】3. 全文零示例
- 无 context 返回 JSON 样例、violations 样例（rule_id/line/fix_hint/severity）、修复前后对照、完整会话流程。
- `fix_hint` 是纯文字描述，无示例时模型难以稳定执行第 4 步。

### 【中】4. 输入/输出未系统定义
- 输入：`--task/--language/--framework` 的必填、可选、取值范围未标；`context` 的 `--context`、`validate` 的 `--code` 参数未提及（`cli.py:17/29`）。
- 输出：validate 实际 JSON 含 `summary`、`syntax_error`、`repair_instruction`（`cli.py:129-143`），SKILL.md 只提 `violations`；`fix_hint` 格式与 `severity` 取值未说明。

### 【中】5. 自检清单用途不明确
- `[自检] ...` 清单未说明是输出给用户、仅内部检查，还是必须放进最终答复。

### 【中】6. verdict 与"第 4 步标记"映射不明确
- 第 4 步说 3 次失败 → 答复标 `[需人工修复]`；第 5 步 verdict 有 `passed/failed/needs_human_review` 三值，何时用 `failed` 何时用 `needs_human_review` 未写明。

### 【低】7. 无"不适用场景"
- 阅读代码、解释代码、纯问答、写文档等不应触发，但无声明，可能过度触发。

### 【低】8. 单文件限制与多文件场景未覆盖
- `validate` 每次只处理一个 `--file`；多文件项目如何批量校验、按何顺序未说明。

## 修改方向（详见审查报告的第五部分"优化后的完整版本"）
1. 收紧触发范围，明确仅覆盖 Python。
2. 补 exit code 2 分支（syntax_error / file not found / 缺参数）。
3. 新增最小示例会话（FastAPI + SQL 注入修复）。
4. 定义 verdict 映射（passed / needs_human_review / failed）。
5. 明确自检清单须在最终答复末尾原样输出。
6. 补充 CLI 不可用时的兜底策略。
7. 补充多文件项目处理说明。
