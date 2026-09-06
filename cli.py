"""cli.py — Secure-Vibe agent toolchain bridge.

This is the unified shell entry point the agent calls once the skill is installed.
Generation is performed by the agent's own LLM (session mode); this tool provides:
  1. security context building (the rule list injected into the agent's decisions)
  2. millisecond-scale validation of agent-generated code
  3. repair instructions (violating lines + fix_hint the agent self-repairs from)
  4. JSONL logging
  5. missed-pattern reports (the rule-iteration loop)

Subcommands:
    context    build the security context (rules/blacklist/template lists)
    validate   validate a code file (--file) or code string (--code)
    sast       scan a whole directory (builtin rules + semgrep + dependency scanners)
    precommit  validate the staged files (git pre-commit hook entry point)
    log        record one complete generation process
    missed     report a new attack pattern that was missed/bypassed
    cwe        query CWE reference knowledge (rule-mining material)
    selftest   self-test (validator + rule loading + log writability + sample suite)

Contract:
    - validate: exit 0=pass  1=violations found  2=error
    - sast/precommit: exit 0=clean  1=findings at the fail-on severity  2=error
    - every JSON output goes to stdout (ensure_ascii=False, UTF-8)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# pipes default to GBK on Windows while agents read UTF-8 — force UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def _candidate_interpreters() -> list[str]:
    """Probe this machine for Python interpreters (pure stdlib; no yaml import needed)."""
    cands: list[str] = []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        for pat in (
            str(Path(local) / "Programs" / "Python" / "Python3*" / "python.exe"),
            r"C:\Python3*\python.exe",
            str(Path(local) / "Programs" / "Python" / "Launcher" / "py.exe"),
            r"C:\Program Files\Python3*\python.exe",
            str(Path(os.environ.get("USERPROFILE", "")) / "Anaconda3" / "python.exe"),
            str(Path(os.environ.get("USERPROFILE", "")) / "miniconda3" / "python.exe"),
        ):
            cands.extend(str(p) for p in glob.glob(pat))
        try:
            r = subprocess.run(["py", "-0p"], capture_output=True, text=True, timeout=10)
            for line in (r.stdout or "").splitlines():
                m = re.search(r"([A-Za-z]:\\[^\s*]+python\.exe)", line)
                if m:
                    cands.append(m.group(1))
        except Exception:
            pass
    else:
        for name in ("python3", "python"):
            p = shutil.which(name)
            if p:
                cands.append(p)
    seen: set[str] = set()
    out = []
    for c in cands:
        c = str(Path(c).resolve()) if Path(c).exists() else c
        if c.lower() not in seen and Path(c).exists():
            seen.add(c.lower())
            out.append(c)
    return out[:6]


def _has_yaml(interpreter: str) -> bool:
    try:
        r = subprocess.run(
            [interpreter, "-c", "import yaml"],
            capture_output=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return r.returncode == 0
    except Exception:
        return False


def _bootstrap_failure(exc: Exception) -> None:
    """Startup self-check: print machine-specific fix commands instead of a bare traceback."""
    fixes: list[dict] = []
    me = sys.executable or "python"
    fixes.append({
        "command": f'"{me}" -m pip install pyyaml',
        "note": "install pyyaml into the current interpreter",
    })
    for cand in _candidate_interpreters():
        if Path(cand).resolve() == Path(me).resolve() if me else False:
            continue
        has = _has_yaml(cand)
        fixes.append({
            "command": f'"{cand}" -m pip install pyyaml' if not has else f'"{cand}" cli.py selftest',
            "note": ("this interpreter already has pyyaml - run the toolchain with it"
                     if has else "alternative interpreter on this machine"),
        })
    fixes.append({
        "command": "python -m pip install pyyaml -i https://pypi.tuna.tsinghua.edu.cn/simple",
        "note": "if pypi.org is unreachable from your network, use the TUNA mirror",
    })
    print(json.dumps({
        "ok": False,
        "error": f"missing dependency: {exc}",
        "problem": "Secure-Vibe needs pyyaml (its only dependency); the current interpreter does not have it",
        "current_interpreter": me,
        "fixes": fixes,
        "after_install": "run: python cli.py selftest  to verify",
    }, ensure_ascii=False, indent=1))


try:
    import yaml
    from core.context_builder import build_prompts, build_repair_prompt
    from core.logger import SecureLogger, compute_manual_diff
    from core.validator import Validator
except ImportError as exc:
    _bootstrap_failure(exc)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent
SKILL_VERSION = "1.0.0"   # keep in sync with the VERSION file; bump on releases


def _load_config() -> dict:
    p = PROJECT_ROOT / "config.yaml"
    if p.is_file():
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {}


def _logger() -> SecureLogger:
    cfg = _load_config().get("logging", {}) or {}
    return SecureLogger(
        log_dir=PROJECT_ROOT / cfg.get("dir", "logs"),
        mask_secrets=cfg.get("mask_secrets", True),
        log_code=cfg.get("log_code", True),
    )


# ---------------------------------------------------------------------------
# subcommand: context
# ---------------------------------------------------------------------------

def cmd_context(args) -> int:
    """Build the security context: rule list + templates + checklist for the agent to follow directly."""
    system_prompt, user_prompt = build_prompts(
        task_description=args.task,
        language=args.language,
        framework=args.framework,
        context=args.context,
        templates_dir=PROJECT_ROOT / "templates" / args.language,
    )
    out = {
        "ok": True,
        "language": args.language,
        "framework": args.framework,
        "system_prompt": system_prompt if args.full else _digest(system_prompt),
        "task": user_prompt,
        "usage": (
            "Generate code strictly following the rules in system_prompt; immediately run "
            "`python cli.py validate --file <your code file>` afterwards, fix per fix_hint on failure, "
            "no more than 3 retries; when done run `python cli.py log` to record."
        ),
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


def _digest(system_prompt: str) -> str:
    """Digested context: keep only rule IDs/descriptions/fix hints and the checklist (token-efficient)."""
    lines = []
    keep = False
    for line in system_prompt.splitlines():
        if line.startswith("## "):
            keep = True
        if keep:
            lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# subcommand: validate
# ---------------------------------------------------------------------------

def cmd_validate(args) -> int:
    """Validate code. exit 0=pass 1=violations 2=error. Attaches repair instructions on violations."""
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            print(json.dumps({"ok": False, "error": f"file not found: {path}"}, ensure_ascii=False))
            return 2
        code = path.read_text(encoding="utf-8", errors="replace")
    elif args.code:
        code = args.code
    else:
        print(json.dumps({"ok": False, "error": "--file or --code is required"}, ensure_ascii=False))
        return 2

    ignore = [r for r in (args.ignore or "").split(",") if r]
    v = Validator(language=args.language, ignore_rules=ignore)
    result = v.validate(code)

    out = {
        "ok": True,
        "passed": result.passed,
        "language": args.language,
        "elapsed_ms": round(result.elapsed_ms, 3),
        "syntax_error": result.error or None,
        "violations": [x.to_dict() for x in result.violations],
        "summary": result.summary(),
    }
    if not result.passed:
        out["repair_instruction"] = (
            f"{len(result.violations)} violation(s) found. Fix them one by one per fix_hint, "
            f"then re-validate; retry at most 3 times; if round 3 still fails, stop and "
            f"mark [needs human review] in your reply."
        )
    print(json.dumps(out, ensure_ascii=False, indent=1))
    # syntax errors -> exit 2 (SKILL.md contract: fix syntax first, re-validate; no repair loop);
    # prevents unparsable code from entering the log flow as exit 0/passed
    if result.error:
        return 2
    return 0 if result.passed else 1


# ---------------------------------------------------------------------------
# subcommand: sast
# ---------------------------------------------------------------------------

def cmd_sast(args) -> int:
    """Scan a whole directory: builtin rules (always) + semgrep + dependency scanners (best-effort)."""
    from core.sast import run_sast

    target = Path(args.path)
    if not target.is_dir():
        print(json.dumps({"ok": False, "error": f"directory not found: {target}"}, ensure_ascii=False))
        return 2

    result = run_sast(target, run_semgrep_flag=not args.no_semgrep,
                      run_deps_flag=not args.no_deps)

    fail_sev = {"high": {"high"}, "any": {"high", "medium", "low"}, "never": set()}[args.fail_on]
    blocking = [f for f in result.findings if f.severity in fail_sev]
    out = {
        "ok": True,
        "passed": not blocking,
        "path": str(target),
        "files_scanned": result.files_scanned,
        "elapsed_ms": round(result.elapsed_ms, 1),
        "engines": result.engines,
        "summary": result.summary(),
        "fail_on": args.fail_on,
        "findings": [f.to_dict() for f in (blocking if not args.full else result.findings)],
        "total_findings": len(result.findings),
    }
    if not out["passed"]:
        out["gate_instruction"] = (
            f"{len(blocking)} finding(s) at fail-on={args.fail_on} severity. "
            f"Fix per fix_hint (semgrep findings include suggested fixes), re-run sast until passed."
        )
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out["passed"] else 1


# ---------------------------------------------------------------------------
# subcommand: precommit
# ---------------------------------------------------------------------------

def cmd_precommit(args) -> int:
    """Validate git staged (or all tracked with --all) files. Pre-commit hook entry point.

    Reads the interpreter from config.yaml when present so the hook runs with the
    install script's chosen Python even when PATH differs.
    """
    if getattr(args, "install_hook", False):
        return _install_hook()
    from core.sast import _detect_lang, _file_ignored
    from core.validator import Validator

    staged = _staged_or_tracked_files(all_files=args.all)
    if staged is None:
        print(json.dumps({"ok": False, "error": "not a git repository (no .git here)"}, ensure_ascii=False))
        return 2

    targets = []
    for rel in staged:
        p = Path(rel)
        if not p.is_file():
            continue
        lang = _detect_lang(p)
        if lang:
            targets.append((p, lang))

    if not targets:
        print(json.dumps({"ok": True, "passed": True, "checked": 0,
                          "note": "no staged code files to validate"}, ensure_ascii=False))
        return 0

    validators: dict[str, Validator] = {}
    findings = []
    for p, lang in targets:
        try:
            code = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _file_ignored(code):
            continue   # deliberate test fixture / demo payload
        v = validators.get(lang)
        if v is None:
            v = Validator(language=lang, taint_analysis=True)
            validators[lang] = v
        result = v.validate(code)
        for viol in result.violations:
            findings.append({
                "file": str(p), "line": viol.line, "rule_id": viol.rule_id,
                "severity": viol.severity, "message": viol.message,
                "fix_hint": viol.fix_hint, "snippet": viol.snippet,
            })

    fail_sev = {"high": {"high"}, "any": {"high", "medium", "low"}, "never": set()}[args.fail_on]
    blocking = [f for f in findings if f["severity"] in fail_sev]
    out = {
        "ok": True,
        "passed": not blocking,
        "checked": len(targets),
        "fail_on": args.fail_on,
        "findings": blocking if not args.full else findings,
        "total_findings": len(findings),
    }
    if blocking:
        out["unblock_hint"] = (
            "Fix the findings, or commit with --no-verify to skip the hook "
            "(the CI gate still runs the same checks on push)."
        )
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out["passed"] else 1


def _staged_or_tracked_files(all_files: bool = False) -> Optional[list[str]]:
    """Staged file list via git diff --cached; all tracked files with --all. None when not a git repo."""
    cmd = ["git", "diff", "--cached", "--name-only"] if not all_files else \
          ["git", "ls-files"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
        return [ln for ln in r.stdout.splitlines() if ln.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return None


def _install_hook() -> int:
    """Install hooks/pre-commit into .git/hooks (idempotent; preserves an existing hook)."""
    git_dir = subprocess.run(["git", "rev-parse", "--git-dir"], capture_output=True,
                             text=True, timeout=15)
    if git_dir.returncode != 0:
        print(json.dumps({"ok": False, "error": "not a git repository"}, ensure_ascii=False))
        return 2
    hooks_dir = Path(git_dir.stdout.strip()) / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    target = hooks_dir / "pre-commit"
    src = PROJECT_ROOT / "hooks" / "pre-commit"
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        if "secure-vibe" in existing or "cli.py" in existing and "precommit" in existing:
            pass   # ours: refresh
        else:
            print(json.dumps({
                "ok": False,
                "error": f"a different pre-commit hook already exists: {target}",
                "note": "merge it manually or wire secure-vibe into .pre-commit-config.yaml",
            }, ensure_ascii=False))
            return 1
    if not src.is_file():
        print(json.dumps({"ok": False, "error": f"hook template missing: {src}"}, ensure_ascii=False))
        return 2
    target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    try:
        target.chmod(0o755)
    except OSError:
        pass
    print(json.dumps({"ok": True, "installed": str(target),
                      "note": "staged files are validated before every commit; skip with --no-verify"}, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# subcommand: log
# ---------------------------------------------------------------------------

def cmd_log(args) -> int:
    """Record one complete generation process to JSONL."""
    code = ""
    if args.file:
        p = Path(args.file)
        if p.is_file():
            code = p.read_text(encoding="utf-8", errors="replace")
        else:
            print(json.dumps({"ok": False, "error": f"file not found: {p}"}, ensure_ascii=False))
            return 2

    diff = ""
    if args.original and args.file:
        op = Path(args.original)
        if op.is_file():
            diff = compute_manual_diff(op.read_text(encoding="utf-8", errors="replace"), code)

    outcome_like = {
        "code": code,
        "passed": args.verdict != "failed",
        "needs_human_review": args.verdict == "needs_human_review",
        "rounds": [],
        "total_retries": args.retries,
        "llm_calls": args.retries + 1,
        "report": "",
        "total_elapsed_ms": 0.0,
    }
    path = _logger().log_generation(
        task_description=args.task,
        language=args.language,
        framework=args.framework,
        context=args.context or "",
        outcome=outcome_like,
        llm_backend="session(agent)",
        manually_modified=bool(diff),
        manual_diff=diff,
    )
    print(json.dumps({"ok": True, "logged": str(path)}, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# subcommand: missed
# ---------------------------------------------------------------------------

def cmd_missed(args) -> int:
    """Report a new attack pattern missed/bypassed (rule-iteration material; promoted to a rule after human review)."""
    path = _logger().log_missed_pattern(
        pattern=args.pattern, source_code=args.code or "", note=args.note or "",
        severity=args.severity)
    print(json.dumps({"ok": True, "logged": str(path),
                      "note": "pattern recorded as pending_review; it will be written to rules/*.yaml after human review"},
                     ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# subcommand: cwe
# ---------------------------------------------------------------------------

def cmd_cwe(args) -> int:
    """Query CWE reference knowledge (GHSA-CySec mining + curated baseline)."""
    ref_path = PROJECT_ROOT / "rules" / "cwe_reference.yaml"
    if not ref_path.is_file():
        print(json.dumps({"ok": False, "error": "cwe_reference.yaml missing; run tools/mine_cwe_rules.py first"},
                         ensure_ascii=False))
        return 2
    data = yaml.safe_load(ref_path.read_text(encoding="utf-8")) or {}
    entries = data.get("cwe", [])
    if args.id:
        hits = [e for e in entries if e.get("id", "").upper() == args.id.upper()]
        print(json.dumps({"ok": True, "query": args.id, "results": hits}, ensure_ascii=False, indent=1))
        return 0 if hits else 1
    print(json.dumps({"ok": True, "count": len(entries),
                      "top": [{"id": e["id"], "name": e.get("name", "")} for e in entries[:20]]},
                     ensure_ascii=False, indent=1))
    return 0


# ---------------------------------------------------------------------------
# subcommands: version / update
# ---------------------------------------------------------------------------

def _installed_version() -> str:
    vf = PROJECT_ROOT / "VERSION"
    return vf.read_text(encoding="utf-8").strip() if vf.is_file() else SKILL_VERSION


def cmd_version(args) -> int:
    """Show the installed version; with --check <url> compares against the remote repo VERSION."""
    out = {
        "ok": True,
        "installed_version": _installed_version(),
        "skill_dir": str(PROJECT_ROOT),
        "git_managed": (PROJECT_ROOT / ".git").is_dir(),
    }
    if args.check:
        url = args.check.rstrip("/")
        try:
            import urllib.request
            with urllib.request.urlopen(f"{url}/raw/main/VERSION", timeout=10) as resp:
                out["latest_version"] = resp.read().decode("utf-8").strip()
            out["up_to_date"] = out["installed_version"] == out.get("latest_version")
            if not out["up_to_date"]:
                out["update_hint"] = "run: python cli.py update (git-managed installs) or re-run the install script"
        except Exception as exc:
            out["ok"] = False
            out["error"] = f"failed to query the remote version: {exc}"
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out.get("ok") else 2


def cmd_update(args) -> int:
    """Update the installed skill.

    - git-managed install (skill dir contains .git) -> git pull the latest code
    - non-git install -> point to re-running the install script (idempotent; copying over = update)
    """
    skill_dir = PROJECT_ROOT
    if not (skill_dir / ".git").is_dir():
        print(json.dumps({
            "ok": False,
            "error": "current install is not git-managed (no .git). To update: re-run install.ps1/install.sh "
                     "(idempotent copy-over = update), or reinstall as git-managed using the install script's "
                     "-Repo/--repo argument (then cli.py update does one-click updates)",
        }, ensure_ascii=False, indent=1))
        return 1

    repo = args.repo
    if not repo:
        # read from the git remote
        try:
            import subprocess
            r = subprocess.run(["git", "-C", str(skill_dir), "remote", "get-url", "origin"],
                               capture_output=True, text=True, timeout=30)
            repo = r.stdout.strip() if r.returncode == 0 else ""
        except Exception:
            repo = ""
    if not repo:
        print(json.dumps({"ok": False, "error": "no remote repo found; specify with --repo <url>"}, ensure_ascii=False))
        return 2

    before = _installed_version()
    try:
        import subprocess
        r = subprocess.run(["git", "-C", str(skill_dir), "pull", "--ff-only"],
                           capture_output=True, text=True, timeout=120)
        success = r.returncode == 0
        output = (r.stdout + r.stderr).strip()
    except Exception as exc:
        success, output = False, str(exc)

    after = _installed_version()
    print(json.dumps({
        "ok": success,
        "version_before": before,
        "version_after": after,
        "updated": before != after,
        "output": output[:1000],
    }, ensure_ascii=False, indent=1))
    return 0 if success else 1


# ---------------------------------------------------------------------------
# subcommand: selftest
# ---------------------------------------------------------------------------

def cmd_selftest(args) -> int:
    """Self-test: rule loading, validator, log writability. For post-install verification."""
    checks = {}
    try:
        v = Validator(language="python")
        checks["rules_loaded"] = len(v.rules)
        r1 = v.validate("eval(user_input)")
        checks["detects_eval"] = (not r1.passed) and any(x.rule_id == "PY-001" for x in r1.violations)
        r2 = v.validate("import secrets\ntoken = secrets.token_urlsafe(32)")
        checks["safe_code_passes"] = r2.passed
        # C rule self-test
        vc = Validator(language="c")
        checks["c_rules_loaded"] = sum(1 for x in vc.rules if x.id.startswith(("C-", "BLC-")))
        r_c = vc.validate('char buf[16];\nsprintf(buf, "%s", name);')
        checks["detects_c_sprintf"] = (not r_c.passed) and any(x.rule_id == "C-002" for x in r_c.violations)
        r_c_safe = vc.validate('printf("hello %d", 42);\nreturn 0;')
        checks["c_safe_passes"] = r_c_safe.passed
        # C++ rule self-test (includes inherited C rules)
        vpp = Validator(language="cpp")
        checks["cpp_rules_loaded"] = len(vpp.rules)
        r_pp = vpp.validate('std::strcpy(dst, src);')
        checks["detects_cpp_strcpy"] = (not r_pp.passed) and any(x.rule_id == "CPP-001" for x in r_pp.violations)
        # PHP rule self-test (includes inherited html/js rules)
        vphp = Validator(language="php")
        checks["php_rules_loaded"] = len(vphp.rules)
        r_php = vphp.validate("<?php system($_GET['cmd']); ?>")
        checks["detects_php_superglobal_exec"] = (not r_php.passed) and any(
            x.rule_id == "BLP-001" for x in r_php.violations)
        r_php_safe = vphp.validate("<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); ?>")
        checks["php_safe_passes"] = r_php_safe.passed
        # HTML rule self-test
        vhtml = Validator(language="html")
        r_html = vhtml.validate('<a href="javascript:alert(1)">x</a>')
        checks["detects_html_js_url"] = (not r_html.passed) and any(
            x.rule_id == "HTML-002" for x in r_html.violations)
        # JS rule self-test
        vjs = Validator(language="js")
        r_js = vjs.validate('eval(userInput);')
        checks["detects_js_eval"] = (not r_js.passed) and any(x.rule_id == "JS-001" for x in r_js.violations)
        # Go / Shell / IaC rule self-tests
        vgo = Validator(language="go")
        r_go = vgo.validate('db.Query("SELECT * FROM t WHERE id=" + id)')
        checks["detects_go_sql_concat"] = (not r_go.passed) and any(x.rule_id == "GO-002" for x in r_go.violations)
        vsh = Validator(language="sh")
        r_sh = vsh.validate('curl -s https://x.sh | sh')
        checks["detects_sh_curl_pipe"] = (not r_sh.passed) and any(x.rule_id == "SH-001" for x in r_sh.violations)
        vdk = Validator(language="dockerfile")
        r_dk = vdk.validate('FROM alpine:3.20\nUSER root')
        checks["detects_docker_root"] = (not r_dk.passed) and any(x.rule_id == "DOCK-001" for x in r_dk.violations)
        vtf = Validator(language="terraform")
        r_tf = vtf.validate('resource "aws_security_group" "x" { ingress { cidr_blocks = ["0.0.0.0/0"] } }')
        checks["detects_tf_open_cidr"] = (not r_tf.passed) and any(x.rule_id == "TF-001" for x in r_tf.violations)
        vpy2 = Validator(language="python")
        r_ssrf = vpy2.validate('requests.get(user_url)')
        checks["detects_py_ssrf"] = (not r_ssrf.passed) and any(x.rule_id == "PY-011" for x in r_ssrf.violations)
        r_ml = vpy2.validate('torch.load(model_path)')
        checks["detects_py_ml_deser"] = (not r_ml.passed) and any(x.rule_id == "PY-021" for x in r_ml.violations)
        # Java / Node / GitHub Actions rule self-tests
        vja = Validator(language="java")
        r_ja = vja.validate('Runtime.getRuntime().exec("sh -c " + userInput)')
        checks["detects_java_exec"] = (not r_ja.passed) and any(x.rule_id == "JAVA-001" for x in r_ja.violations)
        vno = Validator(language="nodejs")
        r_no = vno.validate('exec("sh -c " + userInput)')
        checks["detects_node_exec"] = (not r_no.passed) and any(x.rule_id == "JS-006" for x in r_no.violations)
        vgha = Validator(language="workflow")
        r_gha = vgha.validate('run: echo "hello ${{ github.event.issue.body }}"')
        checks["detects_gha_injection"] = (not r_gha.passed) and any(x.rule_id == "GHA-001" for x in r_gha.violations)
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            lg = SecureLogger(log_dir=Path(td))
            p = lg.log_missed_pattern("selftest", note="install self-test")
            checks["log_writable"] = p.is_file()
        ref = (PROJECT_ROOT / "rules" / "cwe_reference.yaml").is_file()
        checks["cwe_reference"] = ref
        # positive/negative sample suite (zero external deps) — measurable rates,
        # explicitly labeled a small self-test suite, not an authoritative benchmark
        from core.selftest_suite import run_suite
        suite = run_suite()
        checks["sample_suite"] = {
            "total": suite["total"],
            "should_flag": suite["should_flag"],
            "detected": suite["detected"],
            "detection_rate": suite["detection_rate"],
            "false_positives": suite["false_positive_count"],
            "missed": suite["missed"][:5],
            "fp_detail": suite["false_positives"][:5],
            "note": "small self-test suite (自测小样本), not an authoritative benchmark",
        }
        ok = all([checks["rules_loaded"] > 0, checks["detects_eval"],
                  checks["safe_code_passes"], checks["detects_c_sprintf"],
                  checks["c_safe_passes"], checks["detects_cpp_strcpy"],
                  checks["detects_php_superglobal_exec"], checks["php_safe_passes"],
                  checks["detects_html_js_url"], checks["detects_js_eval"],
                  checks["detects_go_sql_concat"], checks["detects_sh_curl_pipe"],
                  checks["detects_docker_root"], checks["detects_tf_open_cidr"],
                  checks["detects_py_ssrf"], checks["detects_py_ml_deser"],
                  checks["detects_java_exec"], checks["detects_node_exec"],
                  checks["detects_gha_injection"],
                  checks["log_writable"],
                  not suite["missed"] and not suite["false_positives"]])
        print(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False, indent=1))
        return 0 if ok else 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc), "checks": checks}, ensure_ascii=False))
        return 2


# ---------------------------------------------------------------------------

def _warn_interpreter_mismatch() -> None:
    """If config.yaml records a chosen interpreter and we are not running under it, warn on stderr.

    The install script writes the probed interpreter into config.yaml (interpreter:);
    running under a different one usually means pyyaml/pip state divergence.
    """
    try:
        recorded = (_load_config().get("interpreter") or "").strip()
    except Exception:
        return
    if not recorded:
        return
    try:
        same = Path(recorded).resolve() == Path(sys.executable).resolve()
    except Exception:
        same = False
    if not same:
        print(
            f"[secure-vibe] note: config.yaml records interpreter {recorded} but you are running {sys.executable}; "
            f"if this fails, re-run: \"{recorded}\" cli.py selftest",
            file=sys.stderr,
        )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secure-vibe-cli", description="Secure-Vibe agent toolchain")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("context", help="build the security context")
    p.add_argument("--task", required=True)
    p.add_argument("--language", default="python")
    p.add_argument("--framework", default="")
    p.add_argument("--context", default="")
    p.add_argument("--full", action="store_true", help="output the full system prompt (digested by default)")
    p.set_defaults(func=cmd_context)

    p = sub.add_parser("validate", help="validate code")
    p.add_argument("--file", help="path to the code file")
    p.add_argument("--code", help="code string (use either --file or --code)")
    p.add_argument("--language", default="python")
    p.add_argument("--ignore", default="", help="rule IDs to ignore, comma-separated")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("sast", help="scan a directory (builtin + semgrep + dependency scanners)")
    p.add_argument("path", help="directory to scan")
    p.add_argument("--fail-on", default="high", choices=["high", "any", "never"],
                   help="severity level that blocks (default: high)")
    p.add_argument("--no-semgrep", action="store_true", help="skip the semgrep engine")
    p.add_argument("--no-deps", action="store_true", help="skip dependency scanners")
    p.add_argument("--full", action="store_true", help="report all findings, not only blocking ones")
    p.set_defaults(func=cmd_sast)

    p = sub.add_parser("precommit", help="validate staged files (pre-commit hook entry)")
    p.add_argument("--all", action="store_true", help="validate all tracked files instead of staged only")
    p.add_argument("--fail-on", default="high", choices=["high", "any", "never"],
                   help="severity level that blocks (default: high)")
    p.add_argument("--full", action="store_true")
    p.add_argument("--install-hook", action="store_true",
                   help="install hooks/pre-commit into .git/hooks (idempotent)")
    p.set_defaults(func=cmd_precommit)

    p = sub.add_parser("log", help="record a generation process")
    p.add_argument("--task", required=True)
    p.add_argument("--file", help="the final code file")
    p.add_argument("--original", help="first generated version, to compute the manual-edit diff")
    p.add_argument("--language", default="python")
    p.add_argument("--framework", default="")
    p.add_argument("--context", default="")
    p.add_argument("--retries", type=int, default=0)
    p.add_argument("--verdict", default="passed", choices=["passed", "failed", "needs_human_review"])
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("missed", help="report a missed-detection pattern")
    p.add_argument("--pattern", required=True)
    p.add_argument("--code", default="")
    p.add_argument("--note", default="")
    p.add_argument("--severity", default="medium", choices=["high", "medium", "low"])
    p.set_defaults(func=cmd_missed)

    p = sub.add_parser("cwe", help="query CWE reference knowledge")
    p.add_argument("--id", default="")
    p.set_defaults(func=cmd_cwe)

    p = sub.add_parser("version", help="show the version (--check <url> compares the remote latest)")
    p.add_argument("--check", default="", help="remote repo URL; compares its VERSION")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("update", help="update (git pull on git-managed installs)")
    p.add_argument("--repo", default="", help="remote repo URL (defaults to the git remote)")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("selftest", help="install self-test")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args(argv)
    if args.cmd not in ("version",):   # version reports interpreter info itself
        _warn_interpreter_mismatch()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
