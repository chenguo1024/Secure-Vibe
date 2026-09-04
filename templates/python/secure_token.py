"""安全模板：secure_token — 安全随机 token 生成（few-shot 示例）.

演示要点:
- 安全用途随机值必须用 secrets 模块（CSPRNG），禁止 random
- 长度建议 ≥ 32 字节
"""
from __future__ import annotations

import secrets
import string


def generate_api_token(nbytes: int = 32) -> str:
    """生成 API token：CSPRNG + URL 安全编码（CWE-338 防护）。"""
    return secrets.token_urlsafe(nbytes)   # 例: 43 字符，约 256 bit 熵


def generate_session_id() -> str:
    """会话 ID：固定 256 bit 熵，不可预测。"""
    return secrets.token_hex(32)


def generate_reset_code(digits: int = 6) -> str:
    """密码重置码：从密码学安全随机源取数字。"""
    return "".join(secrets.choice(string.digits) for _ in range(digits))


def constant_time_equals(a: str, b: str) -> bool:
    """比较 token 时使用恒定时间比较，防时序侧信道。"""
    return secrets.compare_digest(a, b)
