"""core/regression.py — Post-repair regression verification (full-ecosystem detection).

A repair that passes the lint but changes behavior is a failed repair. After a
repair converges, this module runs the project's own test suite (when one is
detectable) so "behavior changed" counts as "repair failed".

Detected ecosystems (in order):
  python  -> tests/ dir or pytest.ini/pyproject.toml  -> python -m pytest -x -q
  node    -> package.json (with a "test" script)      -> npm test
  go      -> go.mod                                    -> go test ./...
  cargo   -> Cargo.toml                                -> cargo test
  make    -> Makefile with a "test:" target            -> make test

Honesty contract: never raises; `ran=False` with the reason when nothing is
detectable or the tool is missing — the caller reports what was verified.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RegressionResult:
    ran: bool
    ecosystem: str = ""
    command: str = ""
    passed: bool = False
    reason: str = ""          # why not ran, when ran=False
    output_tail: str = ""     # last lines of output for diagnosis

    def to_dict(self) -> dict:
        return {
            "ran": self.ran, "ecosystem": self.ecosystem,
            "command": self.command, "passed": self.passed,
            "reason": self.reason, "output_tail": self.output_tail,
        }


def detect_ecosystem(root: Path) -> tuple[str, str]:
    """Detect (ecosystem, command) for the project at root; ("", "") when none."""
    root = Path(root)
    has = lambda name: (root / name).exists()

    if has("tests") or has("pytest.ini") or has("pyproject.toml"):
        # only when pytest is importable in this interpreter
        try:
            import pytest  # noqa: F401
            return "python", "pytest"
        except ImportError:
            pass

    if has("package.json"):
        try:
            pkg = json.loads((root / "package.json").read_text(encoding="utf-8", errors="replace"))
            if pkg.get("scripts", {}).get("test"):
                return "node", "npm test"
        except (json.JSONDecodeError, OSError):
            pass

    if has("go.mod"):
        return "go", "go test ./..."

    if has("Cargo.toml"):
        return "cargo", "cargo test"

    if has("Makefile"):
        try:
            mk = (root / "Makefile").read_text(encoding="utf-8", errors="replace")
            if "test:" in mk:
                return "make", "make test"
        except OSError:
            pass

    return "", ""


def _tool_available(command: str) -> bool:
    binaries = {"pytest": ("pytest", "--version"), "npm test": ("npm", "--version"),
                "go test ./...": ("go", "version"), "cargo test": ("cargo", "--version"),
                "make test": ("make", "--version")}
    import shutil
    b = binaries.get(command)
    if not b:
        return False
    return shutil.which(b[0]) is not None


def run_regression(root: Path, timeout: int = 900) -> RegressionResult:
    """Run the project's test suite; never raises. Honest about what was verified."""
    root = Path(root)
    eco, command = detect_ecosystem(root)
    if not eco:
        return RegressionResult(ran=False, reason="no test suite detected "
                                "(tests/, package.json with test script, go.mod, Cargo.toml, Makefile)")
    if not _tool_available(command):
        return RegressionResult(ran=False, ecosystem=eco, command=command,
                                reason=f"tool not available: {command}")

    cmds: dict[str, list[str]] = {
        "pytest": ["python", "-m", "pytest", "-x", "-q"],
        "npm test": ["npm", "test"],
        "go test ./...": ["go", "test", "./..."],
        "cargo test": ["cargo", "test"],
        "make test": ["make", "test"],
    }
    try:
        r = subprocess.run(cmds[command], cwd=str(root), capture_output=True,
                           text=True, timeout=timeout)
        tail = "\n".join((r.stdout + "\n" + r.stderr).strip().splitlines()[-10:])
        return RegressionResult(ran=True, ecosystem=eco, command=command,
                                passed=r.returncode == 0, output_tail=tail)
    except subprocess.TimeoutExpired:
        return RegressionResult(ran=True, ecosystem=eco, command=command, passed=False,
                                reason=f"timeout after {timeout}s", output_tail="")
    except OSError as exc:
        return RegressionResult(ran=True, ecosystem=eco, command=command, passed=False,
                                reason=str(exc), output_tail="")
