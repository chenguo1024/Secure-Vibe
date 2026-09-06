"""安全模板：db_query — SQL 参数化查询（few-shot 示例）.

演示要点:
- 参数化查询，绝不拼接 SQL
- 输入校验（白名单）
- 资源用 with 管理
"""
from __future__ import annotations

import sqlite3
from typing import Any, Optional

_ALLOWED_SORT_COLUMNS = {"name", "created_at", "id"}  # 白名单：可排序字段


def get_user_by_name(conn: sqlite3.Connection, username: str) -> Optional[dict[str, Any]]:
    """按用户名查询用户 —— 参数化查询，防 SQL 注入（CWE-89）。"""
    if not username or len(username) > 64:
        raise ValueError("invalid username")
    # ? 占位符 + 参数元组：用户输入永远不进入 SQL 字符串本身
    cur = conn.execute("SELECT id, name, email FROM users WHERE name = ?", (username,))
    row = cur.fetchone()
    return {"id": row[0], "name": row[1], "email": row[2]} if row else None


def list_users(conn: sqlite3.Connection, sort_by: str = "id", limit: int = 50) -> list[dict[str, Any]]:
    """列名无法参数化，必须用白名单校验后拼入。"""
    if sort_by not in _ALLOWED_SORT_COLUMNS:
        raise ValueError(f"sort_by must be one of {sorted(_ALLOWED_SORT_COLUMNS)}")
    limit = max(1, min(int(limit), 100))  # 数值边界约束
    # sort_by 已过白名单，limit 已转 int，安全
    cur = conn.execute(f"SELECT id, name FROM users ORDER BY {sort_by} LIMIT ?", (limit,))  # secure-vibe: ignore (whitelisted column name, documented pattern)
    return [{"id": r[0], "name": r[1]} for r in cur.fetchall()]
