"""ast_fixer.py — AST 确定性修复引擎（零 LLM、毫秒级、安全等价改写）.

原理:
  - 解析代码为 AST，用 ast.NodeTransformer 做节点级改写
  - 改写后 ast.unparse 还原源码，再交给校验器复验
  - 只处理"可证明安全等价"的改写；无法确定性修复的违规（如 eval、
    shell=True 字符串命令拆分、pickle 反序列化）保留原样交给 LLM/人工

覆盖的确定性修复（rule_name -> 改写）:
  insecure_random          random.randint/randrange/choice/getrandbits -> secrets.*
  weak_hash                hashlib.md5/sha1 -> hashlib.sha256
  unsafe_yaml_load         yaml.load -> yaml.safe_load（并丢弃 Loader= 参数）
  hardcoded_secret         简单赋值 STR = "明文" -> STR = os.environ.get("STR", "")

用法:
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
    """按规则集合对 AST 做安全等价改写。"""

    def __init__(self, rules: set[str]):
        self.rules = rules
        self.applied: set[str] = set()
        self.need_imports: set[str] = set()
        # 已存在的导入（避免重复插入）
        self.have_imports: set[str] = set()

    # -- 导入收集 -----------------------------------------------------------

    def _scan_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.have_imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.have_imports.add(node.module.split(".")[0] if node.module else "")

    # -- 危险调用改写 -------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> ast.AST:
        # 先递归处理子节点
        self.generic_visit(node)

        # 1) 不安全随机 -> secrets（可证明等价：均为生成随机值，secrets 更安全）
        if "insecure_random" in self.rules and isinstance(node.func, ast.Attribute):
            f = node.func
            if isinstance(f.value, ast.Name) and f.value.id == "random" and f.attr in RANDOM_FIXES:
                new = self._fix_random(node, f.attr)
                if new is not None:
                    self.applied.add("insecure_random")
                    self.need_imports.add("secrets")
                    return ast.copy_location(new, node)

        # 2) 弱哈希 -> sha256（升级为强哈希；安全用途方向正确）
        if "weak_hash" in self.rules:
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                if func.attr in WEAK_HASH_FIXES:
                    func.attr = WEAK_HASH_FIXES[func.attr]
                    self.applied.add("weak_hash")

        # 3) yaml.load -> yaml.safe_load（不带 Loader 时安全等价）
        if "unsafe_yaml_load" in self.rules and isinstance(node.func, ast.Attribute):
            func = node.func
            if isinstance(func.value, ast.Name) and func.value.id == "yaml" and func.attr == "load":
                func.attr = "safe_load"
                # safe_load 不接收 Loader 参数，丢弃之
                node.keywords = [k for k in node.keywords if k.arg and k.arg.lower() != "loader"]
                self.applied.add("unsafe_yaml_load")

        return node

    def _fix_random(self, node: ast.Call, attr: str) -> Optional[ast.AST]:
        """构造 secrets 等价调用。"""
        secrets = lambda name: ast.Attribute(ast.Name("secrets", ast.Load()), name, ast.Load())  # noqa: E731

        if attr == "choice":
            if node.args:
                return ast.Call(secrets("choice"), node.args, [])
            return None
        if attr == "getrandbits":
            if len(node.args) == 1:
                return ast.Call(secrets("randbits"), node.args, [])
            return None
        if attr == "random":  # [0,1) 浮点，丢熵不关键时给 0.0，但这不是等价——交由 LLM
            return None
        if attr == "uniform":
            return None
        if attr == "sample":
            return None
        # randint(a, b) -> secrets.randbelow(b - a + 1) + a
        # randrange(a[, b]) -> secrets.randbelow(b - a) + a  或 randbelow(a)
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

    # -- 硬编码密钥 -> 环境变量 -------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        self.generic_visit(node)
        if "hardcoded_secret" not in self.rules:
            return node
        # 仅处理单一 Name 目标 + 字符串常量值
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return node
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return node
        var = node.targets[0].id
        if len(node.value.value) < 6:
            return node
        # "明文" -> os.environ.get("VAR", "")
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
    """在模块头部（docstring 之后）插入缺少的 import。"""
    missing = transformer.need_imports - transformer.have_imports
    if not missing:
        return code

    # 用 AST 定位 docstring 结束行（单行/多行都正确）
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
    """对可确定性修复的违规做 AST 改写。

    返回 (新代码, 已应用的 rule_name 列表)。
    代码解析失败或无可修复规则时返回原代码 + 空列表。
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
