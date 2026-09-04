"""server.py 启动冒烟测试（README 未要求，但验证 HTTP 服务可用）。"""
import json
import subprocess
import sys
import time
import urllib.request


def _wait_ready(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def main() -> int:
    import os
    py = sys.executable
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(script_dir)
    server = os.path.join(root, "server.py")
    port = 8399
    base = f"http://127.0.0.1:{port}"

    proc = subprocess.Popen(
        [py, server], cwd=root,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not _wait_ready(f"{base}/health"):
            print("SMOKE FAIL: health 不可达")
            return 1
        with urllib.request.urlopen(f"{base}/health", timeout=5) as r:
            health = json.loads(r.read().decode("utf-8"))
        assert health["status"] == "ok", health

        # 校验恶意代码：应返回 passed=False
        body = json.dumps({"code": "eval(user_input)", "language": "python"}).encode("utf-8")
        req = urllib.request.Request(f"{base}/validate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read().decode("utf-8"))
        assert resp["passed"] is False, resp
        assert any(v["rule_id"] == "PY-001" for v in resp["violations"])

        print("SMOKE OK: /health + /validate 均正常，教学路径可用")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
