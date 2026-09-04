"""安全模板：file_upload — 安全文件上传（few-shot 示例）.

演示要点:
- 路径穿越防护（CWE-22）：resolve 后校验仍在目标目录内
- 文件类型白名单（不是黑名单）
- 文件大小限制
- 不信任原始文件名，重命名为随机名
"""
from __future__ import annotations

import secrets
from pathlib import Path

UPLOAD_DIR = Path("/srv/uploads").resolve()
ALLOWED_EXTENSIONS = {".jpg", ".png", ".pdf", ".txt"}      # 白名单
ALLOWED_MIME_PREFIXES = {"image/jpeg", "image/png", "application/pdf", "text/plain"}
MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAGIC_NUMBERS = {b"\xff\xd8\xff": ".jpg", b"\x89PNG\r\n\x1a\n": ".png", b"%PDF-": ".pdf"}


def safe_upload(data: bytes, original_name: str, mime_type: str) -> Path:
    """安全保存上传文件，返回存储路径。

    异常即拒绝上传（fail-closed）。
    """
    # 1. 大小限制（CWE-400）
    if not data or len(data) > MAX_SIZE_BYTES:
        raise ValueError("file too large or empty")

    # 2. 扩展名白名单（CWE-434）
    ext = Path(original_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("extension not allowed")

    # 3. 魔数校验：内容必须与扩展名一致（防伪装）
    expected_magic = next((m for m, e in MAGIC_NUMBERS.items() if data.startswith(m)), None)
    if ext in MAGIC_NUMBERS.values() and expected_magic != ext:
        raise ValueError("content does not match extension")

    # 4. MIME 白名单
    if not any(mime_type.startswith(p) for p in ALLOWED_MIME_PREFIXES):
        raise ValueError("mime type not allowed")

    # 5. 不信任原始文件名：用 CSPRNG 随机名（防路径注入 + 防覆盖）
    dest = UPLOAD_DIR / (secrets.token_hex(16) + ext)

    # 6. 路径穿越最终校验：resolve 后必须仍在 UPLOAD_DIR 内（CWE-22）
    resolved = dest.resolve()
    if not str(resolved).startswith(str(UPLOAD_DIR) + __import__("os").sep):
        raise ValueError("path traversal detected")

    resolved.write_bytes(data)
    return resolved
