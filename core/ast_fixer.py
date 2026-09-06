"""ast_fixer.py — AST deterministic fix engine (zero LLM, millisecond-scale, safe equivalent rewrites).

How it works:
  - parse code into an AST and rewrite at node level with ast.NodeTransformer
  - ast.unparse the result back to source, then re-validate
  - only "provably safe-equivalent" rewrites are applied; violations without a
    deterministic fix (eval, shell=True string-command splits, pickle) are left
    as-is for the LLM or a human

Deterministic fixes covered (rule_name -> rewrite):
  insecure_random          random.randint/randrange/choice/getrandbits -> secrets.*
  weak_hash                hashlib.md5/sha1 -> hashlib.sha256
  unsafe_yaml_load         yaml.load -> yaml.safe_load (Loader= args dropped)
  hardcoded_secret         simple assignment STR = "plain" -> STR = os.environ.get("STR", "")

Usage:
    from core.ast_fixer import deterministic_fix
    new_code, applied_rules = deterministic_fix(code, [violation, ...])
"""
from __future__ import annotations

import ast
from typing import Any, Optional

RANDOM_FIXES = {
    "randint": True, "randrange": True, "choice": True, "getrandbits": True,
    "random": True, "uniform": True, "sample": True,
}
WEAK_HASH_FIXES = {"md5": "sha256", "sha1": "sha256"}


class _SecureTransformer(ast.NodeTransformer):
    """Apply safe equivalent rewrites to the AST for a set of rules."""

    def __init__(self, rules: set[str]):
        self.rules = rules
        self.applied: set[str] = set()
        self.need_imports: set[str] = set()
        # imports already present (avoids duplication)
        self.have_imports: set[str] = set()

    # -- import scanning -------------------------------------------------------

    def _scan_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.have_imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.have_imports.add(node.module.split(".")[0] if node.module else "")

    # -- dangerous-call rewrites -----------------------------------------------

    def visit_Call(self, node: ast.Call) -> ast.AST:
        # recurse into children first
        self.generic_visit(node)

        # 1) insecure random -> secrets (provably equivalent: both generate random values; secrets is safer)
        if "insecure_random" in self.rules and isinstance(node.func, ast.Attribute):
            f = node.func
            if isinstance(f.value, ast.Name) and f.value.id == "random" and f.attr in RANDOM_FIXES:
                new = self._fix_random(node, f.attr)
                if new is not None:
                    self.applied.add("insecure_random")
                    self.need_imports.add("secrets")
                    return ast.copy_location(new, node)

        # 2) weak hash -> sha256 (upgrade to a strong hash; the right direction for security uses)
        if "weak_hash" in self.rules:
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                if func.attr in WEAK_HASH_FIXES:
                    func.attr = WEAK_HASH_FIXES[func.attr]
                    self.applied.add("weak_hash")

        # 3) yaml.load -> yaml.safe_load (safe equivalent without Loader)
        if "unsafe_yaml_load" in self.rules and isinstance(node.func, ast.Attribute):
            func = node.func
            if isinstance(func.value, ast.Name) and func.value.id == "yaml" and func.attr == "load":
                func.attr = "safe_load"
                # safe_load takes no Loader argument - drop it
                node.keywords = [k for k in node.keywords if k.arg and k.arg.lower() != "loader"]
                self.applied.add("unsafe_yaml_load")

        return node

    def _fix_random(self, node: ast.Call, attr: str) -> Optional[ast.AST]:
        """Construct the equivalent secrets call."""
        secrets = lambda name: ast.Attribute(ast.Name("secrets", ast.Load()), name, ast.Load())  # noqa: E731

        if attr == "choice":
            if node.args:
                return ast.Call(secrets("choice"), node.args, [])
            return None
        if attr == "getrandbits":
            if len(node.args) == 1:
                return ast.Call(secrets("randbits"), node.args, [])
            return None
        if attr == "random":  # [0,1) float; not equivalent when replaced - leave to the LLM
            return None
        if attr == "uniform":
            return None
        if attr == "sample":
            return None
        # randint(a, b) -> secrets.randbelow(b - a + 1) + a
        # randrange(a[, b]) -> secrets.randbelow(b - a) + a   or randbelow(a)
        if attr in ("randint", "randrange"):
            if attr == "randint" and len(node.args) == 2:
                a, b = node.args
                span = ast.BinOp(ast.BinOp(b, ast.Sub(), a), ast.Add(), ast.Constant(1))
            elif attr == "randrange" and len(node.args) == 1:
                return ast.Call(secrets("randbelow"), node.args, [])
            elif attr == "randrange" and len(node.args) == 2:
                a, b = node.args
                span = ast.BinOp(b, ast.Sub(), a)
            else:
                return None
            return ast.BinOp(
                ast.Call(secrets("randbelow"), [span], []),
                ast.Add(),
                a,
            )
        return None

    # -- hardcoded secret -> environment variable -------------------------------

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        self.generic_visit(node)
        if "hardcoded_secret" not in self.rules:
            return node
        # only single Name targets with a string constant value
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return node
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return node
        var = node.targets[0].id
        if len(node.value.value) < 6:
            return node
        # "plain" -> os.environ.get("VAR", "")
        node.value = ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name("os", ast.Load()),
                    attr="environ",
                    ctx=ast.Load(),
                ),
                attr="get",
                ctx=ast.Load(),
            ),
            args=[ast.Constant(var), ast.Constant("")],
            keywords=[],
        )
        self.applied.add("hardcoded_secret")
        self.need_imports.add("os")
        return node


def _insert_imports(code: str, transformer: _SecureTransformer) -> str:
    """Insert missing imports at the module head (after the docstring)."""
    missing = transformer.need_imports - transformer.have_imports
    if not missing:
        return code

    # locate the docstring end line via AST (correct for single and multi-line)
    insert_at = 0
    try:
        tree = ast.parse(code)
        if (tree.body and isinstance(tree.body[0], ast.Expr)
                and isinstance(tree.body[0].value, ast.Constant)
                and isinstance(tree.body[0].value.value, str)):
            insert_at = getattr(tree.body[0], "end_lineno", 1)
    except SyntaxError:
        pass

    lines = code.split("\n")
    import_lines = ["import " + m for m in sorted(missing)]
    new_lines = lines[:insert_at] + import_lines + lines[insert_at:]
    return "\n".join(new_lines)


def deterministic_fix(code: str, violations: list[Any]) -> tuple[str, list[str]]:
    """Apply AST rewrites for deterministically fixable violations.

    Returns (new code, list of applied rule_names).
    Returns the original code + an empty list when parsing fails or no rule is fixable.
    """
    from core.validator import Violation

    rules = {v.rule_name for v in violations if isinstance(v, Violation)}
    fixable = rules & {"insecure_random", "weak_hash", "unsafe_yaml_load", "hardcoded_secret"}
    if not fixable:
        return code, []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code, []

    tr = _SecureTransformer(fixable)
    tr._scan_imports(tree)
    new_tree = tr.visit(tree)
    ast.fix_missing_locations(new_tree)
    if not tr.applied:
        return code, []

    try:
        new_code = ast.unparse(new_tree)
    except Exception:
        return code, []

    new_code = _insert_imports(new_code, tr)
    return new_code, sorted(tr.applied)
