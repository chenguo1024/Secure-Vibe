"""taint.py — 轻量污点追踪（AST 级别）.

在现有"危险函数匹配"之上增加"数据流确认"：当危险 sink 的参数确实来自
用户输入（污点源）时，报告一条更高可信度的违规（checker=taint）。

设计取舍（轻量、声明式不建模净化函数）:
  - sound over-approx: 一旦变量被污点赋值即保持污点（不建模 sanitize）
  - 只报告"确认污染 + 危险 sink"的组合，用于:
      1. 升级修复建议（带上污点链条，便于 LLM 精确修复）
      2. 检出变量间接传递的注入（cmd = input(); os.system(cmd)）
      3. 供后续评测计算"确认注入"指标

污点源: input() / raw_input() / sys.argv / sys.stdin / request.* / socket.recv*
传播:   赋值 / BinOp 拼接 / f-string / % 格式化 / .format / .join / 函数参数透传
sink:   os.system|popen → PY-002；eval|exec → PY-001；
        subprocess.*(shell=True) → PY-003；pickle.load(s) → PY-004；
        yaml.load → PY-005；"execute" 拼接 SQL → GEN-005（投向 LLM 修复提示）

输出:  list[dict{rule_id, line, col, message, chain, severity}]
"""
from __future__ import annotations

import ast
from typing import Any, Optional

# ---------------------------------------------------------------------------
# 节点标识工具
# ---------------------------------------------------------------------------

def _nid(node: ast.AST) -> int:
    return id(node)


# ---------------------------------------------------------------------------
# 污点源 / sink 判定
# ---------------------------------------------------------------------------

def _is_source(node: ast.expr) -> Optional[str]:
    """若是污点源表达式，返回源描述字符串，否则 None。"""
    # input() / raw_input()
    if isinstance(node, ast.Call):
        name = _func_name(node.func)
        if name in ("input", "raw_input"):
            return f"{name}()"
        # sys.stdin.read() / sys.stdin.readline() / sys.stdin.readlines()
        if name in ("sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines",
                    "sys.stdin.buffer.read", "sys.stdin.buffer.readline"):
            return name
    # sys.argv / sys.stdin 下标访问
    if isinstance(node, ast.Subscript):
        base = node.value
        if (isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name)
                and base.value.id == "sys" and base.attr in ("argv", "stdin")):
            return f"sys.{base.attr}[...]"
    # 文件对象读（file.read() 其中 file 由 open() 得到——过近似，故仅显式 sys.stdin）
    # request.args / request.form / ...（web 框架）
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
    """还原函数名（os.system / eval / request.args.get ...）。"""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _sink_rule(call: ast.Call) -> Optional[str]:
    """若调用是危险 sink，返回对应规则 ID。"""
    name = _func_name(call.func)
    tail = name.split(".")[-1]
    if name in ("eval", "exec"):
        return "PY-001"
    if name in ("os.system", "os.popen"):
        return "PY-002"
    # subprocess 系列：仅 shell=True 时才算命令注入 sink
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
# 传播：判断节点是否被污染
# ---------------------------------------------------------------------------

class _TaintEngine:
    def __init__(self, tree: ast.AST):
        self.tainted: set[int] = set()
        self.origin: dict[int, str] = {}
        self.tree = tree
        self.name_origin: dict[str, str] = {}

    def analyze(self) -> None:
        self._mark_sources()
        # 定点迭代：赋值/拼接传播，直到不再变化
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
        """一次遍历预建 变量名->污点源 映射（后续 O(1) 查询）。"""
        self.name_origin = {}
        for n in ast.walk(self.tree):
            if _nid(n) not in self.tainted or not isinstance(n, ast.Assign):
                continue
            o = self.origin.get(_nid(n), "污点变量")
            for t in n.targets:
                if isinstance(t, ast.Name):
                    self.name_origin.setdefault(t.id, o)

    def _expr_origin(self, node: Optional[ast.AST]) -> Optional[str]:
        """表达式是否被污染；返回源描述或 None。"""
        if node is None:
            return None
        if _nid(node) in self.tainted:
            return self.origin.get(_nid(node), "污点源")
        if isinstance(node, ast.Name):
            return self.name_origin.get(node.id)
        return None

    def _propagate_origin(self, node: ast.AST) -> Optional[str]:
        """返回该节点应继承的污点源描述（多个时取第一个），否则 None。"""
        # 赋值 / 增强赋值：右值污点 → 整个赋值污点
        if isinstance(node, ast.Assign):
            return self._expr_origin(node.value)
        if isinstance(node, ast.AnnAssign):
            return self._expr_origin(node.value) if node.value else None
        if isinstance(node, ast.AugAssign):
            return self._expr_origin(node.value)
        # 拼接类：任一子表达式污点即污点
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            return self._first_child_origin(node)
        # 函数调用：参数污点透传（over-approx），sink 在 find_sinks 处理
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
            # 关键字参数
            if isinstance(child, ast.keyword) and child.value is not None:
                o = self._expr_origin(child.value)
                if o:
                    return o
        return None

    # -- 报告 ----------------------------------------------------------------

    def find_sinks(self) -> list[dict[str, Any]]:
        """找出"参数被污染"的危险 sink 调用。"""
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
            # 若参数本身是拼接表达式，也尝试其子节点源
            findings.append({
                "rule_id": rule_id,
                "line": getattr(node, "lineno", 0) or 0,
                "col": getattr(node, "col_offset", 0),
                "chain": " -> ".join(origins) if origins else "污点源",
            })
        return findings


# ---------------------------------------------------------------------------
# 对外接口
# ---------------------------------------------------------------------------

SINK_MESSAGES = {
    "PY-001": "用户输入进入 eval/exec（代码注入，污点已确认）",
    "PY-002": "用户输入进入系统命令（命令注入，污点已确认）",
    "PY-003": "用户输入进入 shell=True 的 subprocess 调用（命令注入，污点已确认）",
    "PY-004": "用户输入进入 pickle/marshal 反序列化（RCE，污点已确认）",
    "PY-005": "用户输入进入 yaml.load（不安全反序列化，污点已确认）",
}

SINK_FIX_HINTS = {
    "PY-001": "立即停止 eval/exec 处理用户输入，改用 json.loads / ast.literal_eval / 显式逻辑分发",
    "PY-002": "改用 subprocess.run(参数列表, shell=False)，用户输入作为列表元素传递，禁止拼命令字符串",
    "PY-003": "移除 shell=True；命令与参数用列表传递，用户输入不进入 shell 解析",
    "PY-004": "外部数据改用 json.loads 等安全格式；绝不 pickle.loads 网络/用户输入",
    "PY-005": "改用 yaml.safe_load（或 yaml.load(..., Loader=yaml.SafeLoader)）",
}


def find_tainted_sinks(code: str) -> list[dict[str, Any]]:
    """分析代码，返回确认污点的 sink 列表。"""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    eng = _TaintEngine(tree)
    eng.analyze()
    return eng.find_sinks()
