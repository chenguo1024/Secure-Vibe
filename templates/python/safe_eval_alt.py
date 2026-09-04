"""安全模板：safe_eval_alt — eval/exec 的安全等价替代（few-shot 示例）.

演示要点（对应 PY-001 修复建议）:
- JSON 数据 → json.loads
- 字面量表达式 → ast.literal_eval（只允许字面量，不执行代码）
- 动态逻辑 → 字典分发（映射表），不 eval 函数名字符串
"""
from __future__ import annotations

import ast
import json
from typing import Any, Callable


def parse_json(text: str) -> Any:
    """解析 JSON 数据：替代 eval。"""
    return json.loads(text)


def parse_literal_expression(text: str) -> Any:
    """求值字面量表达式（如 "[1, 2, 3]"、"{'a': 1}"）：
    ast.literal_eval 只解析字面量，绝不执行函数调用/名称引用。
    """
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        raise ValueError("not a literal expression") from None


_OPERATIONS: dict[str, Callable[..., Any]] = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "mul": lambda a, b: a * b,
}


def dispatch_operation(name: str, *args: Any) -> Any:
    """动态逻辑分发：替代 eval(函数名)。操作名白名单 + 字典映射。"""
    op = _OPERATIONS.get(name)
    if op is None:
        raise ValueError(f"unknown operation: {name!r}")
    return op(*args)
