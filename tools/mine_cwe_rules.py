"""mine_cwe_rules.py — 从 GHSA/CVE 数据集挖掘 CWE→修复措施映射，更新 rules/cwe_reference.yaml.

数据来源（任选其一，均为本地 JSONL/JSON 文件）:
  1. GHSA-CySec (ModelScope: couvor/GHSA-CySec) — 需在 ModelScope 申请后下载
     modelscope download --dataset couvor/GHSA-CySec --local_dir <路径>
  2. 任意含 {cwe, fix/remediation} 字段的 JSONL（如日志中人工沉淀的修复记录）

用法:
    python tools/mine_cwe_rules.py <数据集文件或目录> [--out rules/cwe_reference.yaml]

行为:
    - 解析每条样本的 CWE 编号与修复文本
    - 聚合出每个 CWE 的 description（取众数文本）/ fix_direction（修复建议合并）
    - 与现有 rules/cwe_reference.yaml 合并（已存在的 CWE 只补 fix_direction，不覆盖）
    - 变更写入文件并标注 provenance
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("需要 pyyaml: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CWE_PATTERN = re.compile(r"CWE[-_ ]?(\d{1,4})", re.IGNORECASE)


def iter_samples(path: Path):
    """遍历数据集文件（JSONL 或 JSON 数组），逐条产出 dict。"""
    files = [path] if path.is_file() else [p for p in path.rglob("*") if p.suffix in (".jsonl", ".json")]
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if f.suffix == ".jsonl":
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    yield from (x for x in data if isinstance(x, dict))
                elif isinstance(data, dict):
                    # 兼容嵌套结构（GHSA-CySec 的 ChatML: content 字段内含 CWE 文本）
                    yield data
            except json.JSONDecodeError:
                continue


def extract_cwe(sample: dict) -> set[str]:
    """从样本字段中提取 CWE 编号集合。"""
    blob = " ".join(str(v) for v in sample.values() if isinstance(v, (str, int)))
    return {f"CWE-{m}" for m in set(CWE_PATTERN.findall(blob))}


def extract_fix(sample: dict) -> str:
    """提取修复相关文本（启发式字段名匹配）。"""
    keys = ("fix", "remediation", "remedy", "solution", "mitigation", "response", "output")
    for k in keys:
        v = sample.get(k)
        if isinstance(v, str) and 10 < len(v) < 2000:
            return v.strip()
        if isinstance(v, list):
            joined = " ".join(str(x) for x in v)
            if 10 < len(joined) < 2000:
                return joined.strip()
    return ""


def mine(source: Path) -> dict[str, dict]:
    """返回 {CWE-XXX: {description_count, fix_directions: Counter}}。"""
    stats: dict[str, dict] = defaultdict(lambda: {"desc": Counter(), "fix": Counter()})
    n = 0
    for sample in iter_samples(source):
        n += 1
        cwes = extract_cwe(sample)
        if not cwes:
            continue
        fix = extract_fix(sample)
        for cwe in cwes:
            stats[cwe]["fix"][fix[:500]] += 1 if fix else 0
            # ChatML 结构: description 取 role=system 的 content 片段
            desc = sample.get("description") or sample.get("overview") or ""
            if isinstance(desc, str) and desc:
                stats[cwe]["desc"][desc[:500]] += 1
    print(f"扫描样本: {n} 条，命中 CWE: {len(stats)} 个")
    return stats


def merge(stats: dict[str, dict], ref_path: Path) -> list[str]:
    """与现有 cwe_reference.yaml 合并，返回变更的 CWE 列表。"""
    existing = {}
    if ref_path.is_file():
        data = yaml.safe_load(ref_path.read_text(encoding="utf-8")) or {}
        existing = {e.get("id"): e for e in data.get("cwe", []) if isinstance(e, dict)}

    changed = []
    for cwe, s in stats.items():
        top_fix = next((f for f, _ in s["fix"].most_common(1) if f), "")
        top_desc = next((d for d, _ in s["desc"].most_common(1) if d), "")
        if cwe in existing:
            entry = existing[cwe]
            if top_fix and top_fix not in entry.get("fix_direction", ""):
                entry["fix_direction"] = f"{entry.get('fix_direction', '')} | 数据集补充: {top_fix[:200]}"
                entry.setdefault("mined_from", []).append(top_fix[:300])
                changed.append(cwe)
        else:
            existing[cwe] = {
                "id": cwe,
                "name": "mined_" + cwe.lower().replace("-", "_"),
                "severity": "medium",
                "description": top_desc or "（从数据集挖掘，待人工补充）",
                "fix_direction": top_fix or "",
                "mined_from": [top_fix[:300]],
            }
            changed.append(cwe)

    doc = {"cwe": sorted(existing.values(), key=lambda e: e["id"]),
           "_provenance": f"curated baseline + GHSA mining ({datetime.now().isoformat()})"}
    ref_path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(description="从 GHSA/CVE 数据集挖掘 CWE→修复映射")
    ap.add_argument("source", help="数据集文件或目录（JSONL/JSON）")
    ap.add_argument("--out", default=str(PROJECT_ROOT / "rules" / "cwe_reference.yaml"))
    args = ap.parse_args()

    src = Path(args.source)
    if not src.exists():
        print(f"数据源不存在: {src}", file=sys.stderr)
        return 2
    stats = mine(src)
    changed = merge(stats, Path(args.out))
    print(f"更新 {args.out}: 新增/补充 {len(changed)} 个 CWE")
    for cwe in changed[:20]:
        print(f"  - {cwe}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
