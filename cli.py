"""cli.py — Secure-Vibe Agent 工具链桥.

这是 Skill 安装进 Agent 后，Agent 通过 shell 调用的统一入口。
生成由 Agent 自身的 LLM 完成（session 模式），本工具负责：
  1. 构建安全上下文（规则清单，注入 Agent 决策）
  2. 毫秒级校验 Agent 生成的代码
  3. 输出修复指令（违规行 + fix_hint，Agent 据此自我修复）
  4. 记录 JSONL 日志
  5. 漏检模式上报（规则迭代闭环）

子命令:
    context    构建安全上下文（规则/黑名单/模板清单）
    validate   校验代码文件（--file）或代码字符串（--code）
    log        记录一次完整生成过程
    missed     上报漏检/被绕过的新攻击模式
    cwe        查询 CWE 参考知识（规则挖掘素材）
    selftest   自检（校验器+规则加载+日志可写）

约定:
    - validate: exit 0=通过  1=存在违规  2=错误
    - 所有 JSON 输出到 stdout（ensure_ascii=False, UTF-8）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Windows 下管道输出默认 GBK，Agent 通常按 UTF-8 读取 → 强制 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

try:
    import yaml
    from core.context_builder import build_prompts, build_repair_prompt
    from core.logger import SecureLogger, compute_manual_diff
    from core.validator import Validator
except ImportError as exc:
    print(json.dumps({"ok": False, "error": f"missing dependency: {exc}"}, ensure_ascii=False))
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent
SKILL_VERSION = "1.0.0"   # 与 VERSION 文件同步；发布新版本时递增


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
# 子命令: context
# ---------------------------------------------------------------------------

def cmd_context(args) -> int:
    """构建安全上下文：输出规则清单 + 模板 + 自检要求，供 Agent 直接遵循。"""
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
            "请严格按 system_prompt 中的规则生成代码；生成后必须立即调用 "
            "`python cli.py validate --file <代码文件>` 校验，未通过则按 fix_hint 修复，"
            "最多重试 3 次；完成后调用 `python cli.py log` 记录。"
        ),
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


def _digest(system_prompt: str) -> str:
    """压缩版上下文：只保留规则 ID/说明/修复建议和自检要求（省 token）。"""
    lines = []
    keep = False
    for line in system_prompt.splitlines():
        if line.startswith("## "):
            keep = True
        if keep:
            lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 子命令: validate
# ---------------------------------------------------------------------------

def cmd_validate(args) -> int:
    """校验代码。exit 0=通过 1=违规 2=错误。违规时附修复指令。"""
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            print(json.dumps({"ok": False, "error": f"file not found: {path}"}, ensure_ascii=False))
            return 2
        code = path.read_text(encoding="utf-8", errors="replace")
    elif args.code:
        code = args.code
    else:
        print(json.dumps({"ok": False, "error": "需要 --file 或 --code"}, ensure_ascii=False))
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
            f"存在 {len(result.violations)} 处违规。请逐条按 fix_hint 修复后重新校验，"
            f"最多重试 3 次；3 次仍未通过时停止并在答复中标记[需人工修复]。"
        )
    print(json.dumps(out, ensure_ascii=False, indent=1))
    # 语法错误 → exit 2（SKILL.md 约定：先修语法后重新校验，不进修复循环）；
    # 避免"无法解析的代码"以 exit 0/passed 进入日志流程
    if result.error:
        return 2
    return 0 if result.passed else 1


# ---------------------------------------------------------------------------
# 子命令: log
# ---------------------------------------------------------------------------

def cmd_log(args) -> int:
    """记录一次完整生成过程到 JSONL。"""
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
# 子命令: missed
# ---------------------------------------------------------------------------

def cmd_missed(args) -> int:
    """上报漏检/被绕过的新攻击模式（规则迭代闭环素材，人工审核后升级为规则）。"""
    path = _logger().log_missed_pattern(
        pattern=args.pattern, source_code=args.code or "", note=args.note or "",
        severity=args.severity)
    print(json.dumps({"ok": True, "logged": str(path),
                      "note": "该模式已记录为 pending_review，人工审核后写入 rules/*.yaml"},
                     ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# 子命令: cwe
# ---------------------------------------------------------------------------

def cmd_cwe(args) -> int:
    """查询 CWE 参考知识（来自 GHSA-CySec 挖掘 + curated 基线）。"""
    ref_path = PROJECT_ROOT / "rules" / "cwe_reference.yaml"
    if not ref_path.is_file():
        print(json.dumps({"ok": False, "error": "cwe_reference.yaml 不存在，先运行 tools/mine_cwe_rules.py"},
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
# 子命令: version / update
# ---------------------------------------------------------------------------

def _installed_version() -> str:
    vf = PROJECT_ROOT / "VERSION"
    return vf.read_text(encoding="utf-8").strip() if vf.is_file() else SKILL_VERSION


def cmd_version(args) -> int:
    """查询安装的版本；--check <url> 时对比远端仓库的 VERSION。"""
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
                out["update_hint"] = "运行 python cli.py update（git 管理安装）或重新运行 install 脚本"
        except Exception as exc:
            out["ok"] = False
            out["error"] = f"无法查询远端版本: {exc}"
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out.get("ok") else 2


def cmd_update(args) -> int:
    """更新已安装的 Skill。

    - git 管理安装（skill 目录含 .git）→ git pull 拉取最新代码
    - 非 git 安装 → 提示重新运行 install 脚本（幂等，覆盖即更新）
    """
    skill_dir = PROJECT_ROOT
    if not (skill_dir / ".git").is_dir():
        print(json.dumps({
            "ok": False,
            "error": "当前安装非 git 管理（无 .git）。更新方式：重新运行 install.ps1/install.sh（幂等覆盖即更新），"
                     "或用 install 脚本的 -Repo/--repo 参数重装为 git 管理安装（此后可 cli.py update 一键更新）",
        }, ensure_ascii=False, indent=1))
        return 1

    repo = args.repo
    if not repo:
        # 从 git remote 读取
        try:
            import subprocess
            r = subprocess.run(["git", "-C", str(skill_dir), "remote", "get-url", "origin"],
                               capture_output=True, text=True, timeout=30)
            repo = r.stdout.strip() if r.returncode == 0 else ""
        except Exception:
            repo = ""
    if not repo:
        print(json.dumps({"ok": False, "error": "未找到远端仓库，用 --repo <url> 指定"}, ensure_ascii=False))
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
# 子命令: selftest
# ---------------------------------------------------------------------------

def cmd_selftest(args) -> int:
    """自检：规则加载、校验器、日志可写。供安装后验证。"""
    checks = {}
    try:
        v = Validator(language="python")
        checks["rules_loaded"] = len(v.rules)
        r1 = v.validate("eval(user_input)")
        checks["detects_eval"] = (not r1.passed) and any(x.rule_id == "PY-001" for x in r1.violations)
        r2 = v.validate("import secrets\ntoken = secrets.token_urlsafe(32)")
        checks["safe_code_passes"] = r2.passed
        # C 语言规则自检
        vc = Validator(language="c")
        checks["c_rules_loaded"] = sum(1 for x in vc.rules if x.id.startswith(("C-", "BLC-")))
        r_c = vc.validate('char buf[16];\nsprintf(buf, "%s", name);')
        checks["detects_c_sprintf"] = (not r_c.passed) and any(x.rule_id == "C-002" for x in r_c.violations)
        r_c_safe = vc.validate('printf("hello %d", 42);\nreturn 0;')
        checks["c_safe_passes"] = r_c_safe.passed
        # C++ 规则自检（含继承的 C 规则）
        vpp = Validator(language="cpp")
        checks["cpp_rules_loaded"] = len(vpp.rules)
        r_pp = vpp.validate('std::strcpy(dst, src);')
        checks["detects_cpp_strcpy"] = (not r_pp.passed) and any(x.rule_id == "CPP-001" for x in r_pp.violations)
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            lg = SecureLogger(log_dir=Path(td))
            p = lg.log_missed_pattern("selftest", note="安装自检")
            checks["log_writable"] = p.is_file()
        ref = (PROJECT_ROOT / "rules" / "cwe_reference.yaml").is_file()
        checks["cwe_reference"] = ref
        ok = all([checks["rules_loaded"] > 0, checks["detects_eval"],
                  checks["safe_code_passes"], checks["detects_c_sprintf"],
                  checks["c_safe_passes"], checks["detects_cpp_strcpy"],
                  checks["log_writable"]])
        print(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False, indent=1))
        return 0 if ok else 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc), "checks": checks}, ensure_ascii=False))
        return 2


# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secure-vibe-cli", description="Secure-Vibe Agent 工具链")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("context", help="构建安全上下文")
    p.add_argument("--task", required=True)
    p.add_argument("--language", default="python")
    p.add_argument("--framework", default="")
    p.add_argument("--context", default="")
    p.add_argument("--full", action="store_true", help="输出完整 system prompt（默认压缩版）")
    p.set_defaults(func=cmd_context)

    p = sub.add_parser("validate", help="校验代码")
    p.add_argument("--file", help="代码文件路径")
    p.add_argument("--code", help="代码字符串（与 --file 二选一）")
    p.add_argument("--language", default="python")
    p.add_argument("--ignore", default="", help="忽略的规则 ID，逗号分隔")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("log", help="记录生成过程")
    p.add_argument("--task", required=True)
    p.add_argument("--file", help="最终代码文件")
    p.add_argument("--original", help="生成初版代码文件（计算人工修改 diff 用）")
    p.add_argument("--language", default="python")
    p.add_argument("--framework", default="")
    p.add_argument("--context", default="")
    p.add_argument("--retries", type=int, default=0)
    p.add_argument("--verdict", default="passed", choices=["passed", "failed", "needs_human_review"])
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("missed", help="上报漏检模式")
    p.add_argument("--pattern", required=True)
    p.add_argument("--code", default="")
    p.add_argument("--note", default="")
    p.add_argument("--severity", default="medium", choices=["high", "medium", "low"])
    p.set_defaults(func=cmd_missed)

    p = sub.add_parser("cwe", help="查询 CWE 参考")
    p.add_argument("--id", default="")
    p.set_defaults(func=cmd_cwe)

    p = sub.add_parser("version", help="查询版本（--check <url> 对比远端最新版）")
    p.add_argument("--check", default="", help="远端仓库 URL，对比远端 VERSION")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("update", help="更新（git 管理安装时 git pull）")
    p.add_argument("--repo", default="", help="远端仓库 URL（默认读 git remote）")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("selftest", help="安装自检")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
