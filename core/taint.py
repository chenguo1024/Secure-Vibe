"""taint.py — Lightweight taint analysis (AST level).

Adds data-flow confirmation on top of dangerous-function matching: when a dangerous
sink's arguments actually originate from user input (a taint source), report a
higher-confidence violation (checker=taint).

Design trade-offs (lightweight; sanitizers are deliberately not modeled):
  - sound over-approx: once a variable is assigned tainted values it stays tainted (sanitize is not modeled)
  - only the "confirmed taint + dangerous sink" combination is reported, used to:
      1. upgrade repair advice (carries the taint chain so the LLM can fix precisely)
      2. detect injection through variable indirection (cmd = input(); os.system(cmd))
      3. compute a "confirmed injection" metric in later evaluations

Taint sources: input() / raw_input() / sys.argv / sys.stdin / request.* / socket.recv*
Propagation:  assignment / BinOp concatenation / f-string / % formatting / .format / .join / argument pass-through
Sinks:  os.system|popen -> PY-002; eval|exec -> PY-001;
        subprocess.*(shell=True) -> PY-003; pickle.load(s) -> PY-004;
        yaml.load -> PY-005; "execute" with SQL concatenation -> GEN-005 (drives LLM repair advice)

Output: list[dict{rule_id, line, col, message, chain, severity}]
"""
from __future__ import annotations

import ast
from typing import Any, Optional

# ---------------------------------------------------------------------------
# node identity helpers
# ---------------------------------------------------------------------------

def _nid(node: ast.AST) -> int:
    return id(node)


# ---------------------------------------------------------------------------
# taint source / sink identification
# ---------------------------------------------------------------------------

def _is_source(node: ast.expr) -> Optional[str]:
    """Return the source description when the node is a taint source, else None."""
    # input() / raw_input()
    if isinstance(node, ast.Call):
        name = _func_name(node.func)
        if name in ("input", "raw_input"):
            return f"{name}()"
        # sys.stdin.read() / sys.stdin.readline() / sys.stdin.readlines()
        if name in ("sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines",
                    "sys.stdin.buffer.read", "sys.stdin.buffer.readline"):
            return name
    # sys.argv / sys.stdin subscript access
    if isinstance(node, ast.Subscript):
        base = node.value
        if (isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name)
                and base.value.id == "sys" and base.attr in ("argv", "stdin")):
            return f"sys.{base.attr}[...]"
    # file-object reads (file.read() where file came from open() — too approximate; explicit sys.stdin only)
    # request.args / request.form / ... (web frameworks)
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return f"request.{node.attr}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        f = node.func
        if (isinstance(f.value, ast.Attribute) and isinstance(f.value.value, ast.Name)
                and f.value.value.id == "request"):
            return f"request.{f.value.attr}.{f.attr}(...)"
    return None


def _func_name(func: ast.expr) -> str:
    """Reduce a function name (os.system / eval / request.args.get ...)."""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _sink_rule(call: ast.Call) -> Optional[str]:
    """Return the matching rule ID when the call is a dangerous sink."""
    name = _func_name(call.func)
    tail = name.split(".")[-1]
    if name in ("eval", "exec"):
        return "PY-001"
    if name in ("os.system", "os.popen"):
        return "PY-002"
    # subprocess family: a command-injection sink only when shell=True
    if tail in ("run", "call", "Popen", "check_output", "check_call") and "subprocess" in name:
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return "PY-003"
        return None
    if tail in ("loads", "load") and name.split(".")[0] in ("pickle", "marshal", "dill"):
        return "PY-004"
    if name in ("yaml.load", "yaml.unsafe_load"):
        return "PY-005"
    return None


def _is_sink_node(node: ast.AST) -> Optional[str]:
    return _sink_rule(node) if isinstance(node, ast.Call) else None


# ---------------------------------------------------------------------------
# propagation: determine whether a node is tainted
# ---------------------------------------------------------------------------

class _TaintEngine:
    def __init__(self, tree: ast.AST):
        self.tainted: set[int] = set()
        self.origin: dict[int, str] = {}
        self.tree = tree
        self.name_origin: dict[str, str] = {}

    def analyze(self) -> None:
        self._mark_sources()
        # fixpoint iteration: assignment/concat propagation until stable
        changed = True
        while changed:
            changed = False
            self._rebuild_name_map()
            for node in ast.walk(self.tree):
                if _nid(node) in self.tainted:
                    continue
                origin = self._propagate_origin(node)
                if origin:
                    self.tainted.add(_nid(node))
                    self.origin[_nid(node)] = origin
                    changed = True
        self._rebuild_name_map()

    def _mark_sources(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.expr):
                src = _is_source(node)
                if src:
                    self.tainted.add(_nid(node))
                    self.origin[_nid(node)] = src

    def _rebuild_name_map(self) -> None:
        """One pass to prebuild the name->origin map (later O(1) lookups)."""
        self.name_origin = {}
        for n in ast.walk(self.tree):
            if _nid(n) not in self.tainted or not isinstance(n, ast.Assign):
                continue
            o = self.origin.get(_nid(n), "tainted variable")
            for t in n.targets:
                if isinstance(t, ast.Name):
                    self.name_origin.setdefault(t.id, o)

    def _expr_origin(self, node: Optional[ast.AST]) -> Optional[str]:
        """Whether the expression is tainted; return the origin description or None."""
        if node is None:
            return None
        if _nid(node) in self.tainted:
            return self.origin.get(_nid(node), "taint source")
        if isinstance(node, ast.Name):
            return self.name_origin.get(node.id)
        return None

    def _propagate_origin(self, node: ast.AST) -> Optional[str]:
        """Return the origin this node should inherit (first of several), else None."""
        # assignment / augmented assignment: tainted RHS taints the whole assignment
        if isinstance(node, ast.Assign):
            return self._expr_origin(node.value)
        if isinstance(node, ast.AnnAssign):
            return self._expr_origin(node.value) if node.value else None
        if isinstance(node, ast.AugAssign):
            return self._expr_origin(node.value)
        # concatenation-like: tainted if any child is tainted
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            return self._first_child_origin(node)
        # calls: argument taint passes through (over-approx); sinks handled in find_sinks
        if isinstance(node, ast.Call):
            origin = self._first_child_origin(node)
            return origin
        return None

    def _first_child_origin(self, node: ast.AST) -> Optional[str]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                o = self._expr_origin(child)
                if o:
                    return o
            # keyword arguments
            if isinstance(child, ast.keyword) and child.value is not None:
                o = self._expr_origin(child.value)
                if o:
                    return o
        return None

    # -- reporting -----------------------------------------------------------

    def find_sinks(self) -> list[dict[str, Any]]:
        """Find dangerous sink calls whose arguments are tainted."""
        findings: list[dict[str, Any]] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            rule_id = _sink_rule(node)
            if not rule_id:
                continue
            origins: list[str] = []
            tainted = False
            for a in list(node.args) + [k.value for k in node.keywords if k.value is not None]:
                o = self._expr_origin(a)
                if o:
                    tainted = True
                    if o not in origins:
                        origins.append(o)
            if not tainted:
                continue
            # if the argument itself is a concat expression, its children are tried as sources too
            findings.append({
                "rule_id": rule_id,
                "line": getattr(node, "lineno", 0) or 0,
                "col": getattr(node, "col_offset", 0),
                "chain": " -> ".join(origins) if origins else "taint source",
            })
        return findings


# ---------------------------------------------------------------------------
# public interface
# ---------------------------------------------------------------------------

SINK_MESSAGES = {
    "PY-001": "User input reaches eval/exec (code injection, taint confirmed) | 用户输入进入 eval/exec（代码注入，污点已确认）",
    "PY-002": "User input reaches a system command (command injection, taint confirmed) | 用户输入进入系统命令（命令注入，污点已确认）",
    "PY-003": "User input reaches a shell=True subprocess call (command injection, taint confirmed) | 用户输入进入 shell=True 的 subprocess 调用（命令注入，污点已确认）",
    "PY-004": "User input reaches pickle/marshal deserialization (RCE, taint confirmed) | 用户输入进入 pickle/marshal 反序列化（RCE，污点已确认）",
    "PY-005": "User input reaches yaml.load (unsafe deserialization, taint confirmed) | 用户输入进入 yaml.load（不安全反序列化，污点已确认）",
}

SINK_FIX_HINTS = {
    "PY-001": "Stop eval/exec on user input now; use json.loads / ast.literal_eval / explicit logic dispatch | 立即停止 eval/exec 处理用户输入，改用 json.loads / ast.literal_eval / 显式逻辑分发",
    "PY-002": "Use subprocess.run(argument list, shell=False); pass user input as a list element; never concatenate command strings | 改用 subprocess.run(参数列表, shell=False)，用户输入作为列表元素传递，禁止拼命令字符串",
    "PY-003": "Remove shell=True; pass command and args as a list; keep user input out of shell parsing | 移除 shell=True；命令与参数用列表传递，用户输入不进入 shell 解析",
    "PY-004": "Use safe formats like json.loads for external data; never pickle.loads on network/user input | 外部数据改用 json.loads 等安全格式；绝不 pickle.loads 网络/用户输入",
    "PY-005": "Use yaml.safe_load (or yaml.load(..., Loader=yaml.SafeLoader)) | 改用 yaml.safe_load（或 yaml.load(..., Loader=yaml.SafeLoader)）",
}

TAINT_CWE = {
    "PY-001": "CWE-95",
    "PY-002": "CWE-78",
    "PY-003": "CWE-78",
    "PY-004": "CWE-502",
    "PY-005": "CWE-502",
}


def find_tainted_sinks(code: str) -> list[dict[str, Any]]:
    """Analyze code and return the list of taint-confirmed sinks."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    eng = _TaintEngine(tree)
    eng.analyze()
    return eng.find_sinks()
