"""llm_backend.py — Pluggable LLM backend abstraction layer.
# secure-vibe: ignore-file - deliberate demo payload / test fixture, not a real secret

primary mode (skill installed inside an agent):
  session  - follows the agent's own LLM. Generation is done by the model the agent uses;
             the skill only provides deterministic tools (context building / validation / logging),
             with zero API dependencies. Wired either via cli.py (agent shell calls) or via
             session_fn injection (Python calls).

standalone mode (running as a standalone script):
  openai   - OpenAI API (environment variable OPENAI_API_KEY)
  claude   - Anthropic API (environment variable ANTHROPIC_API_KEY)
  ollama   - local Ollama (base_url defaults to http://localhost:11434)
  mock     - for testing: offline, returns preset code (script injection controls its behavior)

Unified interface: backend.generate(system_prompt, user_prompt) -> str
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
    """Unified protocol for all backend implementations."""

    def generate(self, system_prompt: str, user_prompt: str) -> str: ...


class SessionLLM:
    """Follows the caller's LLM: the generation function is injected by the agent environment.

    Usage (inside agent tooling):
        backend = SessionLLM(generate_fn=agent_current_llm_generate)
    """

    def __init__(self, generate_fn: Callable[[str, str], str]):
        if not callable(generate_fn):
            raise ValueError("SessionLLM needs an injected callable: generate_fn(system, user) -> str")
        self._fn = generate_fn

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        return self._fn(system_prompt, user_prompt)


class OpenAIBackend:
    def __init__(self, cfg: LLMConfig):
        try:
            from openai import OpenAI  # lazy import; missing package must not affect other backends
        except ImportError as exc:
            raise ImportError("openai backend requires: pip install openai") from exc
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("Missing environment variable OPENAI_API_KEY")
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
            raise ImportError("claude backend requires: pip install anthropic") from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("Missing environment variable ANTHROPIC_API_KEY")
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
            raise ImportError("ollama backend requires: pip install httpx") from exc
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
    """Testing mock: fully offline.

    Accepts an injectable responses list (returned in call order) or a script function;
    by default returns a snippet containing injection flaws, used to demonstrate the
    validator triggering the repair loop.
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
    """Factory: create a backend instance from config.

    - cfg.backend == "session" requires injecting session_fn (the agent's current LLM).
    - cfg None defaults to MockBackend (no network dependency, works out of the box).
    """
    if cfg is None:
        return MockBackend()
    name = (cfg.backend or "mock").lower()
    if name == "session":
        if session_fn is None:
            raise ValueError("backend=session requires injecting the current LLM generation function via session_fn")
        return SessionLLM(session_fn)
    if name == "mock":
        return MockBackend()  # Mock takes no LLMConfig; return the default instance
    cls = _BACKENDS.get(name)
    if cls is None:
        raise ValueError(f"unknown backend: {name}, available: {list(_BACKENDS)}")
    return cls(cfg)
