"""安全模板：password_hash — 密码哈希与校验（few-shot 示例）.

演示要点:
- 密码存储用 bcrypt/argon2，禁止 md5/sha1/明文
- 密码从环境变量/用户输入读取，绝不硬编码
"""
from __future__ import annotations

import hashlib
import hmac
import os

# 首选 bcrypt / argon2（需 pip install bcrypt）；此处给出无依赖的标准库兜底方案：
# PBKDF2-HMAC-SHA256（OWASP 建议 ≥ 600,000 迭代）
_PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """生成密码哈希。密码来自用户输入，绝不写死在代码里。"""
    if not password or len(password) < 8:
        raise ValueError("password too weak")
    salt = os.urandom(16)  # 每个密码独立随机盐
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """恒定时间比较，防时序攻击（CWE-208）。"""
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            raise ValueError("unknown algorithm")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)  # 恒定时间比较
    except (ValueError, TypeError):
        return False
