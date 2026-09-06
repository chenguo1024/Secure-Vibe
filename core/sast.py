"""core/sast.py — SAST orchestrator: directory scanning + external engine delegation.

Positioning (v2): Secure-Vibe is a *fast linter + engine orchestrator + commit
gate*, not a full SAST. This module:

  1. walks a target directory, maps files to languages (by extension),
  2. runs the built-in Validator on every file (built-in rules, milliseconds),
  3. optionally delegates to semgrep when it is installed (single binary;
     absent locally -> graceful degrade with an install hint, never an error),
  4. optionally runs dependency scanners per detected ecosystem
     (pip-audit / govulncheck / npm audit) and normalizes their findings
     into the same violation shape.

External engines are additive: their findings are merged, never gate the
built-in engine's results, and every engine that did not run is reported as
`skipped` with the reason — honest about what was checked.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.validator import Validator, normalize_language

# extension -> canonical language (kept in sync with validator's alias map)
EXT_LANG: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php",
    ".html": "html", ".htm": "html",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js",
    ".ts": "js", ".tsx": "js",  # approximate: TS scanned as JS
    ".go": "go",
    ".java": "java",
    ".sh": "sh", ".bash": "sh", ".zsh": "sh",
    ".ps1": "sh",              # approximate
    ".yaml": "yaml-iac", ".yml": "yaml-iac",
    ".tf": "terraform", ".tfvars": "terraform",
    ".java": "java",
}

# containerfile names
_DOCKERFILE_NAMES = {"dockerfile", "containerfile"}

# file-level suppression marker: first line `# secure-vibe: ignore-file` marks a
# deliberate test fixture / demo payload; its findings are excluded from the gate
IGNORE_FILE_MARKER = "secure-vibe: ignore-file"


def _file_ignored(code_head: str) -> bool:
    return IGNORE_FILE_MARKER in code_head[:200]


@dataclass
class SastFinding:
    """One finding, normalized across engines."""
    file: str
    line: int
    rule_id: str
    rule_name: str
    severity: str
    message: str
    fix_hint: str
    engine: str            # builtin | semgrep | deps
    snippet: str = ""
    cwe: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "file": self.file, "line": self.line,
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "severity": self.severity, "message": self.message,
            "fix_hint": self.fix_hint, "engine": self.engine,
        }
        if self.snippet:
            d["snippet"] = self.snippet
        if self.cwe:
            d["cwe"] = self.cwe
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class SastResult:
    files_scanned: int = 0
    findings: list[SastFinding] = list
    engines: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def __post_init__(self) -> None:
        if isinstance(self.findings, type):
            self.findings = []

    @property
    def passed(self) -> bool:
        return not self.findings

    def summary(self) -> str:
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return " | ".join(f"{k}={v}" for k, v in sorted(by_sev.items())) or "clean"


def _detect_lang(path: Path) -> Optional[str]:
    name = path.name.lower()
    if name in _DOCKERFILE_NAMES or name.startswith("dockerfile."):
        return "dockerfile"
    return EXT_LANG.get(path.suffix.lower())


def _yaml_iac_lang(path: Path) -> Optional[str]:
    """Disambiguate YAML files: kubernetes manifests vs github-actions workflows vs plain yaml."""
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4000]
    except Exception:
        return None
    if "apiVersion" in head and ("kind:" in head):
        if "cirrus" in head.lower():
            return None
        if "jobs:" in head and ("steps:" in head or "runs-on" in head):
            return "workflow"
        return "kubernetes"
    return None


def _walk(root: Path, max_file_bytes: int = 2_000_000) -> list[tuple[Path, str]]:
    """Collect (path, language) pairs under root, honoring common ignore dirs."""
    ignore = {".git", ".hg", "node_modules", "__pycache__", ".venv", "venv",
              "dist", "build", ".mypy_cache", ".pytest_cache", "logs"}
    out: list[tuple[Path, str]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in ignore for part in p.parts):
            continue
        try:
            if p.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        lang = _detect_lang(p)
        if lang == "yaml-iac":
            lang = _yaml_iac_lang(p)
        if lang:
            out.append((p, lang))
    return out


def _run_builtin(files: list[tuple[Path, str]]) -> tuple[list[SastFinding], int]:
    """Run the built-in validator per file; validators are cached per language."""
    findings: list[SastFinding] = []
    validators: dict[str, Validator] = {}
    n = 0
    for path, lang in files:
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _file_ignored(code):
            continue   # deliberate test fixture / demo payload
        n += 1
        v = validators.get(lang)
        if v is None:
            v = Validator(language=lang, taint_analysis=True)
            validators[lang] = v
        result = v.validate(code)
        rel = str(path)
        for viol in result.violations:
            findings.append(SastFinding(
                file=rel, line=viol.line, rule_id=viol.rule_id,
                rule_name=viol.rule_name, severity=viol.severity,
                message=viol.message, fix_hint=viol.fix_hint,
                engine="builtin", snippet=viol.snippet, cwe=viol.cwe,
            ))
    return findings, n


# --- external engines ---------------------------------------------------------

def semgrep_available() -> bool:
    return _engine_version(["semgrep", "--version"]) is not None


def _engine_version(cmd: list[str]) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "?"
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None


SEMGREP_INSTALL_HINTS = {
    "win32": "semgrep does not support Windows natively: use WSL (wsl pip install semgrep) or Docker "
             "(docker run --rm -v $(pwd):/src returntocorp/semgrep). CI (ubuntu) installs it directly.",
    "default": "pip install semgrep",
}


def run_semgrep(root: Path, timeout: int = 600) -> tuple[list[SastFinding], str]:
    """Run semgrep over root; returns (findings, status).

    status: "ran" | "not_installed" | "error".
    Graceful degrade: never raises; not_installed carries an install hint in engines meta.
    """
    if not semgrep_available():
        return [], "not_installed"
    try:
        r = subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(root)],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode not in (0, 1):   # 1 = findings present, still success
            return [], "error"
        data = json.loads(r.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return [], "error"

    findings: list[SastFinding] = []
    for res in data.get("results", []):
        extra = res.get("extra", {})
        findings.append(SastFinding(
            file=res.get("path", "?"),
            line=int(res.get("start", {}).get("line", 0)),
            rule_id=extra.get("metadata", {}).get("cwe", "") or res.get("check_id", "?"),
            rule_name=str(res.get("check_id", "?")).split(".")[-1],
            severity=extra.get("severity", "WARNING").lower(),
            message=extra.get("message", "")[:300],
            fix_hint=(extra.get("fix") or "")[:300],
            engine="semgrep",
            snippet=(res.get("extra", {}).get("lines", "") or "")[:160],
            cwe=extra.get("metadata", {}).get("cwe", ""),
        ))
    return findings, "ran"


# --- dependency scanners --------------------------------------------------------

def _detect_ecosystems(root: Path) -> list[str]:
    """Detect dependency manifests -> ecosystems to scan."""
    eco = []
    checks = {
        "python": ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"),
        "node": ("package.json", "package-lock.json"),
        "go": ("go.mod", "go.sum"),
    }
    for eco_name, manifests in checks.items():
        if any((root / m).is_file() for m in manifests):
            eco.append(eco_name)
    return eco


def run_dependency_scan(root: Path, timeout: int = 300) -> tuple[list[SastFinding], dict[str, str]]:
    """Run available dependency scanners for detected ecosystems.

    Returns (findings, per-ecosystem status). Never raises.
    Normalizes: pip-audit JSON, govulncheck JSON, npm audit --json.
    """
    findings: list[SastFinding] = []
    status: dict[str, str] = {}
    ecosystems = _detect_ecosystems(root)

    for eco in ecosystems:
        if eco == "python":
            if _engine_version(["pip-audit", "--version"]) is None:
                status["python"] = "pip-audit not installed"
                continue
            r = _run_cmd(["pip-audit", "--format", "json", "-r",
                          str(root / "requirements.txt")] if (root / "requirements.txt").is_file()
                         else ["pip-audit", "--format", "json", str(root)])
            if r is None:
                status["python"] = "pip-audit error"
                continue
            status["python"] = "ran"
            try:
                for item in json.loads(r or "[]"):
                    for fix in item.get("fixes", []) or []:
                        pass
                    findings.append(SastFinding(
                        file=str(root / (item.get("runtime", "requirements.txt"))),
                        line=0,
                        rule_id=f"DEP-{item.get('name', 'pkg').upper()}",
                        rule_name=f"vulnerable dependency: {item.get('name', '?')} {item.get('version', '')}",
                        severity="high" if item.get("fixes") else "medium",
                        message="; ".join(v.get("description", "")[:200] for v in item.get("vulns", [])[:3]),
                        fix_hint="; ".join(v.get("fix_versions", ["upgrade"]) for v in item.get("vulns", [])[:3]) and
                                 f"upgrade to {[v.get('fix_versions') for v in item.get('vulns', [])[:1]]}",
                        engine="deps",
                        extra={"ecosystem": "python", "package": item.get("name"),
                               "version": item.get("version"),
                               "ids": [v.get("id") for v in item.get("vulns", [])]},
                    ))
            except (json.JSONDecodeError, TypeError, AttributeError):
                status["python"] = "pip-audit output parse error"

        elif eco == "node":
            if _engine_version(["npm", "--version"]) is None:
                status["node"] = "npm not installed"
                continue
            r = _run_cmd(["npm", "audit", "--json"], cwd=str(root))
            if r is None:
                status["node"] = "npm audit error"
                continue
            status["node"] = "ran"
            try:
                data = json.loads(r or "{}")
                for key, vuln in (data.get("vulnerabilities") or {}).items():
                    findings.append(SastFinding(
                        file=str(root / "package.json"),
                        line=0, rule_id=f"DEP-{key.upper()}",
                        rule_name=f"vulnerable npm package: {key} ({vuln.get('severity', '?')})",
                        severity=vuln.get("severity", "medium"),
                        message=(vuln.get("title", "") or "")[:300],
                        fix_hint=f"via: {vuln.get('fixAvailable', 'manual review')}",
                        engine="deps",
                        extra={"ecosystem": "node", "package": key,
                               "range": vuln.get("range", "")},
                    ))
            except (json.JSONDecodeError, TypeError, AttributeError):
                status["node"] = "npm audit output parse error"

        elif eco == "go":
            if _engine_version(["govulncheck", "-version"]) is None and \
               _engine_version(["govulncheck", "--version"]) is None:
                status["go"] = "govulncheck not installed"
                continue
            r = _run_cmd(["govulncheck", "-json", "./..."], cwd=str(root))
            if r is None:
                status["go"] = "govulncheck error"
                continue
            status["go"] = "ran"
            for line in (r or "").splitlines():
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                finding = obj.get("finding", {})
                trace = (finding.get("trace") or [{}])[0]
                mod = (trace.get("module") or "")
                if not mod:
                    continue
                findings.append(SastFinding(
                    file=str(root / "go.mod"), line=0,
                    rule_id=f"DEP-{finding.get('osv', 'GO').upper()}",
                    rule_name=f"vulnerable go module: {mod}",
                    severity="high",
                    message=(finding.get("osv", "") or ""),
                    fix_hint="go get -u <module>; see the OSV entry for fixed versions",
                    engine="deps",
                    extra={"ecosystem": "go", "module": mod},
                ))
    return findings, status


def _run_cmd(cmd: list[str], cwd: Optional[str] = None) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=cwd)
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


# --- entry ---------------------------------------------------------------------

def run_sast(root: Path, run_semgrep_flag: bool = True,
             run_deps_flag: bool = True) -> SastResult:
    """Full SAST orchestration: builtin (always) + semgrep/deps (best-effort)."""
    t0 = time.perf_counter()
    files = _walk(Path(root))
    builtin_findings, n_files = _run_builtin(files)

    findings = list(builtin_findings)
    engines: dict[str, Any] = {
        "builtin": {"ran": True, "files": n_files, "findings": len(builtin_findings)},
    }

    if run_semgrep_flag:
        sg_findings, sg_status = run_semgrep(Path(root))
        findings.extend(sg_findings)
        engines["semgrep"] = {
            "ran": sg_status == "ran", "status": sg_status,
            "findings": len(sg_findings),
            "install_hint": SEMGREP_INSTALL_HINTS.get(
                sys.platform, SEMGREP_INSTALL_HINTS["default"]) if sg_status == "not_installed" else "",
        }

    if run_deps_flag:
        dep_findings, dep_status = run_dependency_scan(Path(root))
        findings.extend(dep_findings)
        engines["deps"] = {
            "ecosystems": dep_status, "findings": len(dep_findings),
        }

    return SastResult(
        files_scanned=n_files, findings=findings, engines=engines,
        elapsed_ms=(time.perf_counter() - t0) * 1000,
    )
