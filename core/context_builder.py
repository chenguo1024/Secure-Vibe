"""context_builder.py — Security context builder.

Input: task_description / language / framework / context
Output: built system_prompt and user_prompt

Rule sources: rules/*.yaml + blacklist/*.yaml + templates/<lang>/ (few-shot),
assembled after filtering by language/framework. Prompt composition:
  1. Persona (security coding expert)
  2. General security rule list (cross-language)
  3. Language/framework-specific rules
  4. Banned-pattern blacklist
  5. Safe code templates (few-shot examples)
  6. Output-format requirements (self-check checklist)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Language normalization and inheritance chain (kept in sync with core/validator.py)
try:
    from core.validator import language_chain, normalize_language
except ImportError:  # fallback when context_builder is used standalone
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

# Keywords in the task description -> recommended safe templates to inject (on-demand few-shot, token-aware)
TASK_TEMPLATE_HINTS: list[tuple[str, str]] = [
    ("登录|auth|认证|jwt|会话|session", "auth"),
    ("sql|数据库|database|查询|query|db", "db_query"),
    ("密码|password|哈希|hash|注册", "password_hash"),
    ("token|随机|随机数|密钥|api.?key", "secure_token"),
    ("上传|upload|文件|file", "file_upload"),
]

SYSTEM_PROMPT_HEADER = """\
You are a senior secure-coding expert. Generate code according to the requirements,
and the code must be secure at generation time — never generate insecure code first and patch it later.

Every line you generate must comply with the security rules below. If the requirement itself
demands an insecure implementation (e.g. hardcoded secrets, SQL concatenation), you must
reject that approach and use a safe equivalent instead, with a comment explaining why.\
"""


def load_rules_for_prompt(language: str, rules_dir: Optional[Path] = None,
                          blacklist_dir: Optional[Path] = None) -> dict[str, Any]:
    """Load rules filtered by language; returns {general, language_rules, blacklist}."""
    rules_dir = Path(rules_dir) if rules_dir else PROJECT_ROOT / "rules"
    blacklist_dir = Path(blacklist_dir) if blacklist_dir else PROJECT_ROOT / "blacklist"
    lang_norm = normalize_language(language)

    def _read(d: Path, name: str) -> list[dict]:
        p = d / f"{name}.yaml"
        if not p.is_file():
            return []
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
        return [x for x in data if isinstance(x, dict) and "id" in x]

    # Load by language chain: general + inherited languages + this language (cpp -> general + c + cpp)
    chain = language_chain(lang_norm)
    general = _read(rules_dir, "general")
    lang: list[dict] = []
    for name in chain[1:]:  # skip general
        lang.extend(_read(rules_dir, name))
    blacklist = _read(blacklist_dir, "general")
    for name in chain[1:]:
        blacklist.extend(_read(blacklist_dir, name))
    return {"general": general, "language_rules": lang, "blacklist": blacklist}


def _rule_lines(rules: list[dict]) -> str:
    """Compress a rule list into prompt-ready checklist text."""
    if not rules:
        return "  (none)"
    lines = []
    for r in rules:
        line = f"  - [{r['id']}] {r.get('message', '')}"
        if r.get("cwe"):
            line += f" ({r['cwe']})"
        if r.get("fix_hint"):
            line += f"\n      Correct approach: {r['fix_hint']}"
        lines.append(line)
    return "\n".join(lines)


def _format_checklist(language: str) -> str:
    return """\
Output format requirements (must be followed strictly):
1. Output exactly one runnable code block wrapped in ```<language>, no extra explanation.
2. The code must not contain any blacklisted patterns.
3. User input, external data, commands, SQL and paths must be validated or parameterized.
4. Sensitive config (secrets/passwords) must be read from environment variables or injected config.

After generating, on a new line after the code block output the self-check checklist
(mark each item or state the exemption reason):
[Self-check] SQL injection: OK/N/A | Command injection: OK/N/A | Hardcoded secrets: OK | Weak randomness: OK/N/A | Input validation: OK | TLS: OK/N/A\
"""


def _few_shot(language: str, task_description: str,
              templates_dir: Optional[Path] = None, max_templates: int = 2) -> str:
    """Pick safe templates by task keywords as few-shot examples."""
    lang = normalize_language(language)
    templates_dir = Path(templates_dir) if templates_dir else PROJECT_ROOT / "templates" / lang
    if not templates_dir.is_dir():
        return ""
    # Template file extensions per language
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
        wanted = available[:1]  # fall back to the first available (db_query in python)

    parts = []
    for tpl in wanted:
        p = templates_dir / f"{tpl}.{ext}"
        if not p.is_file():
            continue
        code = p.read_text(encoding="utf-8").strip()
        parts.append(f"### Safe example: {tpl}\n```{lang}\n{code}\n```")
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
    """Build the system_prompt and user_prompt.

    Returns (system_prompt, user_prompt).
    """
    lang = normalize_language(language)
    rules = load_rules_for_prompt(lang, rules_dir, blacklist_dir)

    sections = [SYSTEM_PROMPT_HEADER]

    sections.append("\n## 1. General security rules (cross-language, must comply)\n" + _rule_lines(rules["general"]))
    sections.append(f"\n## 2. {language}-specific rules"
                    + (f" (framework: {framework})" if framework else "") + "\n"
                    + _rule_lines(rules["language_rules"]))
    sections.append("\n## 3. Banned-pattern blacklist (fail immediately, non-negotiable)\n"
                    + _rule_lines(rules["blacklist"]))

    few_shot = _few_shot(lang, task_description, templates_dir)
    if few_shot:
        sections.append("\n## 4. Safe code templates (few-shot — imitate this style)\n" + few_shot)
    else:
        sections.append("\n## 4. Safe code templates\n  (no templates available)")

    sections.append("\n## 5. " + _format_checklist(lang))

    system_prompt = "\n".join(sections)

    user_parts = [f"Task: {task_description.strip()}"]
    if framework:
        user_parts.append(f"Framework/environment: {framework}")
    if context:
        user_parts.append(f"Context/notes:\n{context.strip()}")
    user_prompt = "\n\n".join(user_parts)

    return system_prompt, user_prompt


def build_repair_prompt(code: str, violations_summary: str, language: str = "python") -> str:
    """Build the repair-round user_prompt: violations as error feedback, ask for a full rewrite."""
    return (
        f"Your previous code failed the security validation with the following violations:\n\n"
        f"{violations_summary}\n\n"
        f"Previous code:\n```{language}\n{code}\n```\n\n"
        f"Please regenerate the complete code:\n"
        f"1. Fix every violation above, none may be missed.\n"
        f"2. Keep the original behavior unchanged.\n"
        f"3. Output only the fixed complete code (wrapped in ```{language}) + the self-check checklist, no explanation."
    )


def build_local_rewrite_prompt(code: str, violation_lines: str, language: str = "python") -> str:
    """Build the local-rewrite prompt: rewrite only the violating snippet to reduce regression."""
    return (
        f"Only the specified lines of the code below have security violations; everything else stays unchanged.\n\n"
        f"Violating lines and reasons:\n{violation_lines}\n\n"
        f"Complete code:\n```{language}\n{code}\n```\n\n"
        f"Output the fixed complete code (wrapped in ```{language}), changing only the violating lines "
        f"and their necessary supporting code. Keep all other lines as-is. No explanation."
    )
