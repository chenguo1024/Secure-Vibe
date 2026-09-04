"""llm_backend.py — LLM 可插拔后端抽象层.

primary 模式（Skill 安装在 Agent 内）:
  session  - 跟随 Agent 自身的 LLM。生成由 Agent 当前所用模型完成，
             Skill 只提供确定性工具（上下文构建/校验/日志），零 API 依赖。
             通过 cli.py（Agent shell 调用）或 session_fn 注入（Python 调用）两种方式接入。

standalone 模式（独立脚本运行时）:
  openai   - OpenAI API（环境变量 OPENAI_API_KEY）
  claude   - Anthropic API（环境变量 ANTHROPIC_API_KEY）
  ollama   - 本地 Ollama（base_url 默认 http://localhost:11434）
  mock     - 测试用，不联网，返回预置代码（可注入脚本控制其行为）

统一接口：backend.generate(system_prompt, user_prompt) -> str
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional, Protocol


@dataclass
class LLMConfig:
    backend: str = "session"
    model: str = ""
    temperature: float = 0.2
    max_tokens: int = 2048
    timeout: int = 60
    base_url: str = ""


class LLMBackend(Protocol):
    """所有后端实现的统一协议。"""

    def generate(self, system_prompt: str, user_prompt: str) -> str: ...


class SessionLLM:
    """跟随调用方的 LLM：由 Agent 环境注入生成函数。

    用法（在 Agent 工具内使用时）:
        backend = SessionLLM(generate_fn=agent_current_llm_generate)
    """

    def __init__(self, generate_fn: Callable[[str, str], str]):
        if not callable(generate_fn):
            raise ValueError("SessionLLM 需要注入 callable: generate_fn(system, user) -> str")
        self._fn = generate_fn

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        return self._fn(system_prompt, user_prompt)


class OpenAIBackend:
    def __init__(self, cfg: LLMConfig):
        try:
            from openai import OpenAI  # 延迟导入，未安装时不影响其他后端
        except ImportError as exc:
            raise ImportError("使用 openai 后端请先: pip install openai") from exc
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("缺少环境变量 OPENAI_API_KEY")
        kwargs: dict = {"api_key": api_key, "timeout": cfg.timeout}
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url
        self.client = OpenAI(**kwargs)
        self.model = cfg.model or "gpt-4o-mini"
        self.cfg = cfg

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            temperature=self.cfg.temperature,
            max_tokens=self.cfg.max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return resp.choices[0].message.content or ""


class ClaudeBackend:
    def __init__(self, cfg: LLMConfig):
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError("使用 claude 后端请先: pip install anthropic") from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("缺少环境变量 ANTHROPIC_API_KEY")
        self.client = anthropic.Anthropic(api_key=api_key, timeout=cfg.timeout)
        self.model = cfg.model or "claude-sonnet-4-20250514"
        self.cfg = cfg

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=self.cfg.max_tokens,
            temperature=self.cfg.temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


class OllamaBackend:
    def __init__(self, cfg: LLMConfig):
        try:
            import httpx
        except ImportError as exc:
            raise ImportError("使用 ollama 后端请先: pip install httpx") from exc
        self.base_url = cfg.base_url or "http://localhost:11434"
        self.model = cfg.model or "qwen2.5-coder:7b"
        self.cfg = cfg
        self._httpx = httpx

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self._httpx.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "options": {"temperature": self.cfg.temperature},
            },
            timeout=self.cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", "")


class MockBackend:
    """测试用 Mock：不联网。

    可注入 responses 列表（按调用次序返回）或脚本函数，
    默认返回一段带注入漏洞的代码，用于演示校验器触发修复循环。
    """

    DEFAULT_RESPONSE = '''\
```python
import sqlite3
API_KEY = "sk-hardcoded-secret-key-123456"

def login(username, password):
    conn = sqlite3.connect("app.db")
    sql = f"SELECT * FROM users WHERE name='{username}' AND pwd='{password}'"
    row = conn.execute(sql).fetchone()
    import random
    token = random.randint(100000, 999999)
    return token
```'''

    def __init__(
        self,
        responses: Optional[list[str]] = None,
        script: Optional[Callable[[str, str, int], str]] = None,
    ):
        self.responses = list(responses) if responses else []
        self.script = script
        self.call_count = 0

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        idx = self.call_count
        self.call_count += 1
        if self.script is not None:
            return self.script(system_prompt, user_prompt, idx)
        if idx < len(self.responses):
            return self.responses[idx]
        return self.DEFAULT_RESPONSE


_BACKENDS = {
    "openai": OpenAIBackend,
    "claude": ClaudeBackend,
    "ollama": OllamaBackend,
}


def create_backend(cfg: Optional[LLMConfig] = None,
                   session_fn: Optional[Callable[[str, str], str]] = None) -> LLMBackend:
    """工厂函数：按配置创建后端实例。

    - cfg.backend == "session" 时需要注入 session_fn（Agent 当前 LLM）。
    - cfg 为 None 时默认使用 MockBackend（无网络依赖，开箱即用）。
    """
    if cfg is None:
        return MockBackend()
    name = (cfg.backend or "mock").lower()
    if name == "session":
        if session_fn is None:
            raise ValueError("backend=session 时必须通过 session_fn 注入当前 LLM 的生成函数")
        return SessionLLM(session_fn)
    if name == "mock":
        return MockBackend()  # Mock 不接受 LLMConfig，直接返回默认实例
    cls = _BACKENDS.get(name)
    if cls is None:
        raise ValueError(f"未知后端: {name}，可选: {list(_BACKENDS)}")
    return cls(cfg)
