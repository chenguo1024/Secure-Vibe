"""安全模板：auth — 安全用户登录接口（few-shot 示例）.

演示要点（对应成功标准"用户登录接口"）:
- 参数化 SQL 查询（防注入）
- 密码恒定时间校验（防时序攻击）
- CSPRNG 会话 token
- 通用错误信息（防用户枚举）
- 登录限速（防爆破）
"""
from __future__ import annotations

import secrets
import sqlite3
import time
from typing import Any, Optional

from password_hash import verify_password

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300


class LoginLimiter:
    """简单内存限速器（生产环境建议 Redis + 指数退避）。"""

    def __init__(self) -> None:
        self._attempts: dict[str, list[float]] = {}

    def too_many_attempts(self, username: str) -> bool:
        now = time.time()
        recent = [t for t in self._attempts.get(username, []) if now - t < WINDOW_SECONDS]
        self._attempts[username] = recent
        return len(recent) >= MAX_ATTEMPTS

    def record_failure(self, username: str) -> None:
        self._attempts.setdefault(username, []).append(time.time())


def login(conn: sqlite3.Connection, username: str, password: str,
          limiter: LoginLimiter) -> Optional[str]:
    """用户登录：成功返回会话 token，失败返回 None。

    安全点:
    1. 参数化查询 —— 防 SQL 注入（CWE-89）
    2. verify_password 恒定时间比较 —— 防时序攻击
    3. secrets.token_urlsafe —— CSPRNG 会话 token（CWE-338）
    4. 统一错误信息 —— 防用户名枚举（CWE-204）
    5. 登录限速 —— 防暴力破解（CWE-307）
    """
    if not username or not password or len(username) > 64 or len(password) > 128:
        return None
    if limiter.too_many_attempts(username):
        return None

    row = conn.execute(
        "SELECT id, pwd_hash FROM users WHERE name = ?", (username,)  # 参数化
    ).fetchone()

    if row is None or not verify_password(password, row[1]):
        limiter.record_failure(username)
        return None  # 用户不存在与密码错误返回一致，防枚举

    return secrets.token_urlsafe(32)  # 安全会话 token
