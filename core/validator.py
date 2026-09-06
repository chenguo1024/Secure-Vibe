"""validator.py — Real-time security validator (three engines: AST dangerous calls + regex blacklist + taint analysis).

Input: code string + language type
Output: ValidationResult (pass/fail + structured violation list)

Design goal: millisecond-scale (<50ms per run), no heavy tools like Semgrep.
Rule sources: rules/*.yaml (general rules) + blacklist/*.yaml (language blacklists);
adding/removing rule files never requires touching this module.
Taint engine: core/taint.py (Python only; confirms user input reaching dangerous sinks).
"""
from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:  # Python 3.9+ compatible import
    import yaml
except ImportError as exc:  # pragma: no cover
    raise ImportError("Secure-Vibe requires pyyaml: pip install pyyaml") from exc

PROJECT_ROOT = Path(__file__).resolve().parent.parent

from core.taint import SINK_FIX_HINTS, SINK_MESSAGES, TAINT_CWE, find_tainted_sinks  # noqa: E402

# ---------------------------------------------------------------------------
# Multi-language support
# ---------------------------------------------------------------------------

# Language alias normalization: c++/C++/cxx are unified to cpp
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

# Language inheritance chains:
#   cpp  loads c.yaml (C code is largely valid C++; C rules apply to C++)
#   php  loads html + js (PHP templates commonly mix HTML/JS fragments, web rules cover them)
#   html loads js (inline <script> fragments are covered by JS rules)
LANGUAGE_INHERITS = {
    "cpp": ["c"],
    "php": ["html", "js"],
    "html": ["js"],
}


def normalize_language(language: str) -> str:
    """Normalize language aliases: 'C++'/'c++' -> 'cpp', 'Python' -> 'python'."""
    return LANGUAGE_ALIASES.get(language.strip().lower(), language.strip().lower())


def language_chain(language: str) -> list[str]:
    """Rule loading chain: general + inherited languages + this language, e.g. cpp -> [general, c, cpp]."""
    chain = ["general"]
    for base in LANGUAGE_INHERITS.get(language, []):
        chain.append(base)
    chain.append(language)
    # dedupe while preserving order
    seen: set[str] = set()
    return [x for x in chain if not (x in seen or seen.add(x))]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    """A single violation record."""
    rule_id: str            # rule ID, e.g. PY-001
    rule_name: str          # rule name, e.g. dangerous_eval
    line: int               # violating line (1-based)
    column: int             # violating column
    snippet: str            # violating code snippet
    message: str            # human-readable description
    severity: str           # high / medium / low
    fix_hint: str           # repair advice (fed back to the LLM)
    cwe: str = ""           # corresponding CWE id (e.g. CWE-95)
    checker: str = ""       # source engine: ast / regex / taint
    template: str = ""      # safe template name for high-risk items (deterministic replacement)

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
    """Validation result."""
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    elapsed_ms: float = 0.0
    language: str = ""
    error: str = ""         # validator-side error (e.g. unparsable code)

    @property
    def has_high(self) -> bool:
        return any(v.severity == "high" for v in self.violations)

    def summary(self) -> str:
        """Human-readable summary for LLM feedback or reports."""
        if self.passed:
            return "PASS: no security violations detected."
        lines = [f"FAIL: {len(self.violations)} security violation(s) detected:"]
        for i, v in enumerate(self.violations, 1):
            lines.append(
                f"  [{i}] {v.rule_id}({v.severity}) line {v.line}: {v.message}\n"
                f"      code: {v.snippet}\n"
                f"      fix: {v.fix_hint}"
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
# Rule model
# ---------------------------------------------------------------------------

class Rule:
    """A single rule loaded from YAML.

    YAML fields:
      id, name, severity, message, fix_hint, cwe, template
      match:                 # matching methods (either or both)
        ast_calls: [...]     #   dangerous function calls (dot paths), e.g. os.system
        ast_kwargs: {...}    #   keyword-argument constraints, e.g. subprocess.call: {shell: "literal-true"}
        regex: [...]         #   regex pattern list
        regex_flags: "i"     #   regex flags (i=ignore case)
      exclude_regex: [...]   #   exclusion patterns (matches inside comments/docstrings do not count)
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
# Validator
# ---------------------------------------------------------------------------

class Validator:
    """Real-time security validator.

    Usage:
        v = Validator(language="python")           # auto-loads default rules
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
        # blacklist files share the rules format; merge-load them
        raw += self._load_yaml_files(blacklist_dir, self.language)
        self.rules: list[Rule] = [
            Rule(item) for item in raw if item.get("id") not in ignore_rules
        ]

    # -- rule loading --------------------------------------------------------

    @staticmethod
    def _load_yaml_files(directory: Path, language: str) -> list[dict[str, Any]]:
        """Load <dir>/{general,inherited,language}.yaml along the language chain; returns the rule list."""
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

    # -- validation entry ----------------------------------------------------

    def validate(self, code: str) -> ValidationResult:
        t0 = time.perf_counter()
        violations: list[Violation] = []
        parse_error = ""

        # Engine 1: AST analysis (Python only; non-Python skip AST/taint and use the regex engine)
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

        # Engine 2: regex blacklist (runs even when AST fails; tolerates code fragments)
        for rule in self.rules:
            if rule.patterns:
                violations.extend(self._check_regex(code, rule))

        # Engine 3: lightweight taint analysis (Python only, when parseable) — confirms user input reaching dangerous sinks
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

    # -- AST engine ----------------------------------------------------------

    def _check_ast(self, tree: ast.AST, code: str, rule: Rule) -> list[Violation]:
        found: list[Violation] = []
        lines = code.splitlines()
        for node in ast.walk(tree):
            # check dangerous function calls: eval / exec / os.system / pickle.loads ...
            if rule.ast_calls and isinstance(node, ast.Call):
                full = self._call_name(node.func)
                if not full:
                    continue
                # exact match: os.system(...) hits os.system
                if full in rule.ast_calls:
                    found.append(self._violation(rule, node, lines, "ast"))
                    continue
                # tail matching only for bare function names (from os import system; system(...) case);
                # prefixed full paths (e.g. json.loads) must not false-positive on a tail collision with pickle.loads
                if "." not in full:
                    tails = {c.split(".")[-1] for c in rule.ast_calls}
                    if full in tails:
                        found.append(self._violation(rule, node, lines, "ast"))
                        continue

            # check keyword-argument constraints: subprocess.call(cmd, shell=True)
            if rule.ast_kwargs and isinstance(node, ast.Call):
                fn = self._call_name(node.func)
                if not fn:
                    continue
                for target_fn, kw_rules in rule.ast_kwargs.items():
                    # exact full-path match, or bare-name tail match (from-import case)
                    if fn == target_fn or ("." not in fn and fn.split(".")[-1] == target_fn.split(".")[-1]):
                        for kw in node.keywords:
                            if kw.arg in kw_rules:
                                expected = kw_rules[kw.arg]
                                if self._kw_matches(kw.value, expected):
                                    found.append(self._violation(rule, node, lines, "ast"))
        return found

    @staticmethod
    def _call_name(func: ast.expr) -> str:
        """Reduce an ast expression to a dot-path name: ast.Attribute/Name -> 'os.system'."""
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
        """Check whether the keyword value matches the blacklist constraint.

        expected values:
          "literal-true"  -> literal True
          "literal-false" -> literal False
          a string        -> exact constant string value
        """
        if expected == "literal-true":
            return isinstance(value, ast.Constant) and value.value is True
        if expected == "literal-false":
            return isinstance(value, ast.Constant) and value.value is False
        if isinstance(expected, str):
            return isinstance(value, ast.Constant) and value.value == expected
        return False

    # -- regex engine --------------------------------------------------------

    def _check_regex(self, code: str, rule: Rule) -> list[Violation]:
        found: list[Violation] = []
        for lineno, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            # skip pure comment lines
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
                    break  # report each rule at most once per line
        return found

    # -- taint analysis ------------------------------------------------------

    def _merge_taint(self, tree: ast.AST, code: str, violations: list[Violation]) -> list[Violation]:
        """Append deep taint confirmations; shallow matches on the same (rule_id, line) yield to the taint conclusion."""
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
                message=SINK_MESSAGES.get(f["rule_id"], "User input reaches a dangerous call (taint confirmed)")
                        + f" | taint chain: {f['chain']}",
                severity="high",
                fix_hint=SINK_FIX_HINTS.get(f["rule_id"], ""),
                cwe=TAINT_CWE.get(f["rule_id"], ""),
                checker="taint",
            ))

        # dedupe: drop ast/regex shallow hits on the same (rule_id, line), keep the taint conclusion
        taint_keys = {(v.rule_id, v.line) for v in taint_violations}
        kept = [v for v in violations if (v.rule_id, v.line) not in taint_keys]
        return kept + taint_violations

    # -- utilities -----------------------------------------------------------

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
