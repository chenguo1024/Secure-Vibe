"""安全模板：secure_config — 配置/密钥注入（few-shot 示例）.

演示要点:
- 密钥/密码一律从环境变量读取，绝不硬编码（CWE-798）
- 启动时校验必需配置，缺失即快速失败
"""
from __future__ import annotations

import os


def get_required_config(name: str) -> str:
    """读取必需配置项，缺失即抛错（fail-fast，避免带默认密钥运行）。"""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"missing required config: {name} (set it via environment)")
    return value


def get_database_url() -> str:
    """数据库连接串从环境读取，绝不写死在代码里。"""
    return get_required_config("DATABASE_URL")


def get_api_key() -> str:
    """API Key 从环境读取。"""
    return get_required_config("API_KEY")


def get_secret_masked() -> str:
    """调试需要展示密钥时只输出掩码。"""
    key = get_api_key()
    return key[:3] + "*" * max(len(key) - 4, 0) + key[-1:]
