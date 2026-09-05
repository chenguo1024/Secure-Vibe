"""context_builder.py — 安全上下文构建器.

输入：task_description / language / framework / context
输出：构建好的 system_prompt 和 user_prompt

规则来源：rules/*.yaml + blacklist/*.yaml + templates/<lang>/（few-shot），
按语言/框架筛选后拼装。Prompt 组成：
  1. 角色设定（安全编码专家）
  2. 通用安全规则清单
  3. 特定语言/框架规则
  4. 禁用模式黑名单
  5. 安全代码模板（few-shot 示例）
  6. 输出格式要求（自检清单）
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 语言归一化与继承链（与 core/validator.py 保持一致）
try:
    from core.validator import language_chain, normalize_language
except ImportError:  # 独立使用 context_builder 时的兜底
    LANGUAGE_ALIASES = {
        "c++": "cpp", "cxx": "cpp", "cc": "cpp", "py": "python", "py3": "python",
        "javascript": "js", "htm": "html", "node": "js", "nodejs": "js",
        "golang": "go", "bash": "sh", "shell": "sh", "zsh": "sh",
        "docker": "dockerfile", "containerfile": "dockerfile",
        "k8s": "kubernetes", "kube": "kubernetes", "tf": "terraform", "hcl": "terraform",
        "workflow": "github-actions", "gha": "github-actions", "github_actions": "github-actions",
    }
    LANGUAGE_INHERITS = {"cpp": ["c"], "php": ["html", "js"], "html": ["js"]}

    def normalize_language(language: str) -> str:
        return LANGUAGE_ALIASES.get(language.strip().lower(), language.strip().lower())

    def language_chain(language: str) -> list[str]:
        chain = ["general"]
        for base in LANGUAGE_INHERITS.get(language, []):
            chain.append(base)
        chain.append(language)
        seen: set[str] = set()
        return [x for x in chain if not (x in seen or seen.add(x))]

# 任务描述中的关键词 -> 推荐加载的安全模板（few-shot 按需注入，控制 token 消耗）
TASK_TEMPLATE_HINTS: list[tuple[str, str]] = [
    ("登录|auth|认证|jwt|会话|session", "auth"),
    ("sql|数据库|database|查询|query|db", "db_query"),
    ("密码|password|哈希|hash|注册", "password_hash"),
    ("token|随机|随机数|密钥|api.?key", "secure_token"),
    ("上传|upload|文件|file", "file_upload"),
]

SYSTEM_PROMPT_HEADER = """\
你是一名资深安全编码专家（Secure Coding Expert）。你的任务是根据需求生成代码，
并且必须在生成时就保证安全性——不允许先生成不安全代码再修补。

你生成的每一行代码都必须遵守下面的安全规则。若需求本身要求不安全的实现
（例如硬编码密钥、拼接 SQL），你必须拒绝该实现方式并采用安全等价方案，同时注释说明。\
"""


def load_rules_for_prompt(language: str, rules_dir: Optional[Path] = None,
                          blacklist_dir: Optional[Path] = None) -> dict[str, Any]:
    """加载并按语言筛选规则，返回 {general, language_rules, blacklist}。"""
    rules_dir = Path(rules_dir) if rules_dir else PROJECT_ROOT / "rules"
    blacklist_dir = Path(blacklist_dir) if blacklist_dir else PROJECT_ROOT / "blacklist"
    lang_norm = normalize_language(language)

    def _read(d: Path, name: str) -> list[dict]:
        p = d / f"{name}.yaml"
        if not p.is_file():
            return []
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
        return [x for x in data if isinstance(x, dict) and "id" in x]

    # 按语言链加载：general + 继承语言 + 本语言（如 cpp -> general + c + cpp）
    chain = language_chain(lang_norm)
    general = _read(rules_dir, "general")
    lang: list[dict] = []
    for name in chain[1:]:  # 跳过 general
        lang.extend(_read(rules_dir, name))
    blacklist = _read(blacklist_dir, "general")
    for name in chain[1:]:
        blacklist.extend(_read(blacklist_dir, name))
    return {"general": general, "language_rules": lang, "blacklist": blacklist}


def _rule_lines(rules: list[dict]) -> str:
    """把规则列表压缩为 prompt 用的清单文本。"""
    if not rules:
        return "  （无）"
    lines = []
    for r in rules:
        line = f"  - [{r['id']}] {r.get('message', '')}"
        if r.get("cwe"):
            line += f"（{r['cwe']}）"
        if r.get("fix_hint"):
            line += f"\n      正确做法: {r['fix_hint']}"
        lines.append(line)
    return "\n".join(lines)


def _format_checklist(language: str) -> str:
    return """\
输出格式要求（必须严格遵守）:
1. 只输出一段完整的可运行代码，用 ```<language> 代码块包裹，不要额外解释。
2. 代码中不得出现任何黑名单模式。
3. 用户输入、外部数据、命令、SQL、路径必须经过校验或参数化处理。
4. 敏感配置（密钥/密码）一律从环境变量或配置注入读取。

生成完成后，在代码块之后另起一行输出自检清单（逐项打勾或说明豁免原因）:
[自检] SQL注入: OK/N/A | 命令注入: OK/N/A | 硬编码密钥: OK | 弱随机: OK/N/A | 输入校验: OK | TLS: OK/N/A\
"""


def _few_shot(language: str, task_description: str,
              templates_dir: Optional[Path] = None, max_templates: int = 2) -> str:
    """按任务关键词挑选安全模板作为 few-shot 示例。"""
    lang = normalize_language(language)
    templates_dir = Path(templates_dir) if templates_dir else PROJECT_ROOT / "templates" / lang
    if not templates_dir.is_dir():
        return ""
    # 模板文件扩展名按语言：python -> .py，c -> .c，cpp -> .cpp，php/html/js 同名
    ext = {"python": "py", "c": "c", "cpp": "cpp",
           "php": "php", "html": "html", "js": "js",
           "go": "go", "sh": "sh", "java": "java",
           "dockerfile": "dockerfile", "kubernetes": "yaml",
           "terraform": "tf", "github-actions": "yml"}.get(lang, "py")
    available = sorted(p.stem for p in templates_dir.glob(f"*.{ext}"))
    wanted: list[str] = []
    for pattern, tpl in TASK_TEMPLATE_HINTS:
        if len(wanted) >= max_templates:
            break
        if re.search(pattern, task_description, re.IGNORECASE) and tpl in available:
            wanted.append(tpl)
    if not wanted:
        wanted = available[:1]  # 默认给第一个可用示例（python 下即 db_query）

    parts = []
    for tpl in wanted:
        p = templates_dir / f"{tpl}.{ext}"
        if not p.is_file():
            continue
        code = p.read_text(encoding="utf-8").strip()
        parts.append(f"### 安全示例：{tpl}\n```{lang}\n{code}\n```")
    return "\n\n".join(parts)


def build_prompts(
    task_description: str,
    language: str = "python",
    framework: str = "",
    context: str = "",
    rules_dir: Optional[Path] = None,
    blacklist_dir: Optional[Path] = None,
    templates_dir: Optional[Path] = None,
) -> tuple[str, str]:
    """构建 system_prompt 和 user_prompt。

    返回 (system_prompt, user_prompt)。
    """
    lang = normalize_language(language)
    rules = load_rules_for_prompt(lang, rules_dir, blacklist_dir)

    sections = [SYSTEM_PROMPT_HEADER]

    sections.append("\n## 一、通用安全规则（跨语言，必须遵守）\n" + _rule_lines(rules["general"]))
    sections.append(f"\n## 二、{language} 特定规则"
                    + (f"（框架：{framework}）" if framework else "") + "\n"
                    + _rule_lines(rules["language_rules"]))
    sections.append("\n## 三、禁用模式黑名单（出现即失败，无商量余地）\n"
                    + _rule_lines(rules["blacklist"]))

    few_shot = _few_shot(lang, task_description, templates_dir)
    if few_shot:
        sections.append("\n## 四、安全代码模板（few-shot，模仿此风格）\n" + few_shot)
    else:
        sections.append("\n## 四、安全代码模板\n  （无可用模板）")

    sections.append("\n## 五、" + _format_checklist(lang))

    system_prompt = "\n".join(sections)

    user_parts = [f"任务：{task_description.strip()}"]
    if framework:
        user_parts.append(f"框架/环境：{framework}")
    if context:
        user_parts.append(f"上下文/补充说明：\n{context.strip()}")
    user_prompt = "\n\n".join(user_parts)

    return system_prompt, user_prompt


def build_repair_prompt(code: str, violations_summary: str, language: str = "python") -> str:
    """构建修复轮的 user_prompt：违规信息作为错误反馈，要求重新生成。"""
    return (
        f"你上一轮生成的代码未通过安全校验，存在以下违规：\n\n"
        f"{violations_summary}\n\n"
        f"上一轮代码：\n```{language}\n{code}\n```\n\n"
        f"请重新生成完整代码：\n"
        f"1. 逐条修复上述所有违规，不得遗漏。\n"
        f"2. 保持原有功能不变。\n"
        f"3. 只输出修复后的完整代码（```{language} 包裹）+ 自检清单，不要解释。"
    )


def build_local_rewrite_prompt(code: str, violation_lines: str, language: str = "python") -> str:
    """构建局部重写 prompt：只重写违规片段，降低退化风险。"""
    return (
        f"以下代码只有指定行存在安全违规，其余部分保持不变。\n\n"
        f"违规行及原因：\n{violation_lines}\n\n"
        f"完整代码：\n```{language}\n{code}\n```\n\n"
        f"请输出修复后的完整代码（```{language} 包裹），只改动违规行及其必要的关联代码，"
        f"其余行保持原样。不要解释。"
    )
