"""validator.py — 实时安全校验器（三引擎：AST 危险调用 + 正则黑名单 + 污点追踪）.

输入：代码字符串 + 语言类型
输出：ValidationResult（通过/不通过 + 结构化违规列表）

设计目标：毫秒级（<50ms/次），不依赖 Semgrep 等重型工具。
规则来源：rules/*.yaml（通用规则）+ blacklist/*.yaml（语言黑名单），
规则文件增删改无需改动本模块代码。
污点引擎：core/taint.py（仅 Python，确认用户输入直达危险 sink）。
"""
from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:  # Python 3.9+ 兼容导入
    import yaml
except ImportError as exc:  # pragma: no cover
    raise ImportError("Secure-Vibe 需要 pyyaml: pip install pyyaml") from exc

PROJECT_ROOT = Path(__file__).resolve().parent.parent

from core.taint import SINK_FIX_HINTS, SINK_MESSAGES, TAINT_CWE, find_tainted_sinks  # noqa: E402

# ---------------------------------------------------------------------------
# 多语言支持
# ---------------------------------------------------------------------------

# 语言别名归一化：用户写 c++/C++/cxx 时统一为 cpp
LANGUAGE_ALIASES = {
    "c++": "cpp",
    "cxx": "cpp",
    "cc": "cpp",
    "py": "python",
    "py3": "python",
    "javascript": "js",
    "htm": "html",
    "node": "js",
    "nodejs": "js",
    "golang": "go",
    "bash": "sh",
    "shell": "sh",
    "zsh": "sh",
    "docker": "dockerfile",
    "containerfile": "dockerfile",
    "k8s": "kubernetes",
    "kube": "kubernetes",
    "tf": "terraform",
    "hcl": "terraform",
    "workflow": "github-actions",
    "gha": "github-actions",
    "github_actions": "github-actions",
}

# 语言继承链：
#   cpp  加载 c.yaml（C 代码基本是合法 C++，C 规则对 C++ 同样适用）
#   php  加载 html + js（PHP 模板中常混 HTML/JS 片段，网页规则同样覆盖）
#   html 加载 js（内联 <script> 片段同样被 JS 规则覆盖）
LANGUAGE_INHERITS = {
    "cpp": ["c"],
    "php": ["html", "js"],
    "html": ["js"],
}


def normalize_language(language: str) -> str:
    """语言别名归一化：'C++'/'c++' -> 'cpp'，'Python' -> 'python'。"""
    return LANGUAGE_ALIASES.get(language.strip().lower(), language.strip().lower())


def language_chain(language: str) -> list[str]:
    """规则加载链：general + 继承语言 + 本语言。如 cpp -> [general, c, cpp]。"""
    chain = ["general"]
    for base in LANGUAGE_INHERITS.get(language, []):
        chain.append(base)
    chain.append(language)
    # 去重保持顺序
    seen: set[str] = set()
    return [x for x in chain if not (x in seen or seen.add(x))]


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    """单条违规记录。"""
    rule_id: str            # 规则 ID，如 PY-001
    rule_name: str          # 规则名，如 dangerous_eval
    line: int               # 违规所在行（1-based）
    column: int             # 违规所在列
    snippet: str            # 违规代码片段
    message: str            # 人读说明
    severity: str           # high / medium / low
    fix_hint: str           # 修复建议（反馈给 LLM）
    cwe: str = ""           # 对应 CWE 编号（如 CWE-95）
    checker: str = ""       # 来源引擎：ast / regex
    template: str = ""      # 高危项对应的安全模板名（确定性替换用）

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "message": self.message,
            "severity": self.severity,
            "fix_hint": self.fix_hint,
            "cwe": self.cwe,
            "checker": self.checker,
            "template": self.template,
        }


@dataclass
class ValidationResult:
    """校验结果。"""
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    elapsed_ms: float = 0.0
    language: str = ""
    error: str = ""         # 校验器自身异常（如代码无法解析）

    @property
    def has_high(self) -> bool:
        return any(v.severity == "high" for v in self.violations)

    def summary(self) -> str:
        """人读摘要，用于反馈给 LLM 或生成报告。"""
        if self.passed:
            return "PASS: 未检测到安全违规。"
        lines = [f"FAIL: 检测到 {len(self.violations)} 处安全违规:"]
        for i, v in enumerate(self.violations, 1):
            lines.append(
                f"  [{i}] {v.rule_id}({v.severity}) 第{v.line}行: {v.message}\n"
                f"      代码: {v.snippet}\n"
                f"      修复: {v.fix_hint}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "elapsed_ms": round(self.elapsed_ms, 3),
            "language": self.language,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# 规则模型
# ---------------------------------------------------------------------------

class Rule:
    """从 YAML 加载的单条规则。

    YAML 字段：
      id, name, severity, message, fix_hint, cwe, template
      match:                 # 匹配方式（二选一或同时）
        ast_calls: [...]     #   危险函数调用（点路径），如 os.system
        ast_kwargs: {...}    #   函数参数约束，如 subprocess.call: {shell: "literal-true"}
        regex: [...]         #   正则模式列表
        regex_flags: "i"     #   正则 flags（i=忽略大小写）
      exclude_regex: [...]   #   排除模式（如注释、docstring 中出现不算）
    """

    def __init__(self, data: dict[str, Any]):
        self.id: str = data["id"]
        self.name: str = data.get("name", self.id.lower())
        self.severity: str = data.get("severity", "medium")
        self.message: str = data.get("message", "")
        self.fix_hint: str = data.get("fix_hint", "")
        self.cwe: str = data.get("cwe", "")
        self.template: str = data.get("template", "")
        match = data.get("match", {})
        self.ast_calls: list[str] = list(match.get("ast_calls", []))
        self.ast_kwargs: dict[str, Any] = dict(match.get("ast_kwargs", {}))
        flags_map = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
        flag_char = match.get("regex_flags", "")
        self.regex_flags = flags_map.get(flag_char, 0)
        self.patterns: list[re.Pattern[str]] = [
            re.compile(p, self.regex_flags) for p in match.get("regex", [])
        ]
        self.exclude: list[re.Pattern[str]] = [
            re.compile(p) for p in match.get("exclude_regex", [])
        ]


# ---------------------------------------------------------------------------
# 校验器
# ---------------------------------------------------------------------------

class Validator:
    """实时安全校验器。

    用法:
        v = Validator(language="python")           # 自动加载默认规则
        result = v.validate(code_str)
        if not result.passed: print(result.summary())
    """

    def __init__(
        self,
        language: str = "python",
        rules_dir: Optional[Path] = None,
        blacklist_dir: Optional[Path] = None,
        ignore_rules: Optional[list[str]] = None,
        taint_analysis: bool = True,
    ):
        self.language = normalize_language(language)
        self.taint_analysis = taint_analysis and self.language == "python"
        rules_dir = Path(rules_dir) if rules_dir else PROJECT_ROOT / "rules"
        blacklist_dir = Path(blacklist_dir) if blacklist_dir else PROJECT_ROOT / "blacklist"
        ignore_rules = ignore_rules or []

        raw = self._load_yaml_files(rules_dir, self.language)
        # blacklist 文件与 rules 文件格式相同，合并加载
        raw += self._load_yaml_files(blacklist_dir, self.language)
        self.rules: list[Rule] = [
            Rule(item) for item in raw if item.get("id") not in ignore_rules
        ]

    # -- 规则加载 -----------------------------------------------------------

    @staticmethod
    def _load_yaml_files(directory: Path, language: str) -> list[dict[str, Any]]:
        """按语言链加载 <dir>/{general,继承语言,language}.yaml，返回规则列表。"""
        items: list[dict[str, Any]] = []
        if not directory.is_dir():
            return items
        for name in language_chain(language):
            path = directory / f"{name}.yaml"
            if not path.is_file():
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            if isinstance(data, list):
                items.extend(d for d in data if isinstance(d, dict) and "id" in d)
        return items

    # -- 校验入口 -----------------------------------------------------------

    def validate(self, code: str) -> ValidationResult:
        t0 = time.perf_counter()
        violations: list[Violation] = []
        parse_error = ""

        # 引擎1: AST 分析（仅 Python；非 Python 语言跳过 AST/污点引擎，走正则引擎）
        tree = None
        parse_error = ""
        if self.language == "python":
            try:
                tree = ast.parse(code)
            except SyntaxError as exc:
                parse_error = f"syntax_error: line {exc.lineno}: {exc.msg}"

        if tree is not None:
            for rule in self.rules:
                if rule.ast_calls or rule.ast_kwargs:
                    violations.extend(self._check_ast(tree, code, rule))

        # 引擎2: 正则黑名单（无论 AST 是否可解析都执行，容忍片段代码）
        for rule in self.rules:
            if rule.patterns:
                violations.extend(self._check_regex(code, rule))

        # 引擎3: 轻量污点追踪（仅 Python，代码可解析时）——确认用户输入直达危险 sink
        if self.taint_analysis and tree is not None:
            violations = self._merge_taint(tree, code, violations)

        elapsed = (time.perf_counter() - t0) * 1000
        return ValidationResult(
            passed=not violations,
            violations=violations,
            elapsed_ms=elapsed,
            language=self.language,
            error=parse_error,
        )

    # -- AST 引擎 -----------------------------------------------------------

    def _check_ast(self, tree: ast.AST, code: str, rule: Rule) -> list[Violation]:
        found: list[Violation] = []
        lines = code.splitlines()
        for node in ast.walk(tree):
            # 检查危险函数调用: eval / exec / os.system / pickle.loads ...
            if rule.ast_calls and isinstance(node, ast.Call):
                full = self._call_name(node.func)
                if not full:
                    continue
                # 精确匹配: os.system(...) 命中 os.system
                if full in rule.ast_calls:
                    found.append(self._violation(rule, node, lines, "ast"))
                    continue
                # 尾段匹配仅用于裸函数名（from os import system; system(...) 场景），
                # 带前缀的完整路径（如 json.loads）不得因尾段撞上 pickle.loads 而误报
                if "." not in full:
                    tails = {c.split(".")[-1] for c in rule.ast_calls}
                    if full in tails:
                        found.append(self._violation(rule, node, lines, "ast"))
                        continue

            # 检查关键字参数约束: subprocess.call(cmd, shell=True)
            if rule.ast_kwargs and isinstance(node, ast.Call):
                fn = self._call_name(node.func)
                if not fn:
                    continue
                for target_fn, kw_rules in rule.ast_kwargs.items():
                    # 完整路径精确匹配，或裸函数名尾段匹配（from-import 场景）
                    if fn == target_fn or ("." not in fn and fn.split(".")[-1] == target_fn.split(".")[-1]):
                        for kw in node.keywords:
                            if kw.arg in kw_rules:
                                expected = kw_rules[kw.arg]
                                if self._kw_matches(kw.value, expected):
                                    found.append(self._violation(rule, node, lines, "ast"))
        return found

    @staticmethod
    def _call_name(func: ast.expr) -> str:
        """把 ast 表达式还原为点路径名: ast.Attribute/Name -> 'os.system'。"""
        parts: list[str] = []
        node: ast.expr = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _kw_matches(value: ast.expr, expected: Any) -> bool:
        """检查关键字参数值是否符合黑名单约束。

        expected 取值:
          "literal-true"  -> 字面量 True
          "literal-false" -> 字面量 False
          字符串          -> 常量字符串值
        """
        if expected == "literal-true":
            return isinstance(value, ast.Constant) and value.value is True
        if expected == "literal-false":
            return isinstance(value, ast.Constant) and value.value is False
        if isinstance(expected, str):
            return isinstance(value, ast.Constant) and value.value == expected
        return False

    # -- 正则引擎 -----------------------------------------------------------

    def _check_regex(self, code: str, rule: Rule) -> list[Violation]:
        found: list[Violation] = []
        for lineno, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            # 跳过纯注释行
            if stripped.startswith("#"):
                continue
            if any(p.search(stripped) for p in rule.exclude):
                continue
            for pattern in rule.patterns:
                m = pattern.search(stripped)
                if m:
                    found.append(
                        Violation(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            line=lineno,
                            column=m.start(),
                            snippet=stripped[:120],
                            message=rule.message,
                            severity=rule.severity,
                            fix_hint=rule.fix_hint,
                            cwe=rule.cwe,
                            checker="regex",
                            template=rule.template,
                        )
                    )
                    break  # 每行每条规则只报一次
        return found

    # -- 污点追踪 -----------------------------------------------------------

    def _merge_taint(self, tree: ast.AST, code: str, violations: list[Violation]) -> list[Violation]:
        """追加深层污点确认结果；同一 (rule_id, line) 的浅层匹配让位于污点结论。"""
        findings = find_tainted_sinks(code)
        if not findings:
            return violations

        taint_violations: list[Violation] = []
        for f in findings:
            taint_violations.append(Violation(
                rule_id=f["rule_id"],
                rule_name=f["rule_id"],
                line=f["line"],
                column=f["col"],
                snippet=code.splitlines()[f["line"] - 1].strip()[:120] if 0 < f["line"] <= len(code.splitlines()) else "",
                message=SINK_MESSAGES.get(f["rule_id"], "用户输入直达危险调用（污点已确认）")
                        + f"；污点链条: {f['chain']}",
                severity="high",
                fix_hint=SINK_FIX_HINTS.get(f["rule_id"], ""),
                cwe=TAINT_CWE.get(f["rule_id"], ""),
                checker="taint",
            ))

        # 去重：同 (rule_id, line) 的 ast/regex 浅层命中删除，保留污点结论
        taint_keys = {(v.rule_id, v.line) for v in taint_violations}
        kept = [v for v in violations if (v.rule_id, v.line) not in taint_keys]
        return kept + taint_violations

    # -- 工具 ---------------------------------------------------------------

    def _violation(self, rule: Rule, node: ast.AST, lines: list[str], checker: str) -> Violation:
        lineno = getattr(node, "lineno", 0) or 0
        snippet = lines[lineno - 1].strip()[:120] if 0 < lineno <= len(lines) else ""
        return Violation(
            rule_id=rule.id,
            rule_name=rule.name,
            line=lineno,
            column=getattr(node, "col_offset", 0),
            snippet=snippet,
            message=rule.message,
            severity=rule.severity,
            fix_hint=rule.fix_hint,
            cwe=rule.cwe,
            checker=checker,
            template=rule.template,
        )
