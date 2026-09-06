"""mine_cwe_rules.py — Mine CWE->remediation mappings from GHSA/CVE datasets and update rules/cwe_reference.yaml.

Data sources (pick one; all are local JSONL/JSON files):
  1. GHSA-CySec (ModelScope: couvor/GHSA-CySec) — apply for access on ModelScope, then download
     modelscope download --dataset couvor/GHSA-CySec --local_dir <path>
  2. any JSONL with {cwe, fix/remediation} fields (e.g. human-curated fixes from your logs)

Usage:
      python tools/mine_cwe_rules.py <dataset file or dir> [--out rules/cwe_reference.yaml]

Behavior:
    - parse each sample's CWE ids and fix text
    - aggregate each CWE's description (majority text) / fix_direction (merged fix advice)
    - merge into the existing rules/cwe_reference.yaml (existing CWEs only gain fix_direction, never overwritten)
    - write the changes and annotate provenance
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
    print("pyyaml required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CWE_PATTERN = re.compile(r"CWE[-_ ]?(\d{1,4})", re.IGNORECASE)


def iter_samples(path: Path):
    """Iterate a dataset file (JSONL or JSON array) yielding dicts one by one."""
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
                    # tolerate nested structures (GHSA-CySec ChatML: CWE text inside the content field)
                    yield data
            except json.JSONDecodeError:
                continue


def extract_cwe(sample: dict) -> set[str]:
    """Extract the set of CWE ids from a sample's fields."""
    blob = " ".join(str(v) for v in sample.values() if isinstance(v, (str, int)))
    return {f"CWE-{m}" for m in set(CWE_PATTERN.findall(blob))}


def extract_fix(sample: dict) -> str:
    """Extract fix-related text (heuristic field-name matching)."""
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
    """Return {CWE-XXX: {description_count, fix_directions: Counter}}."""
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
            # ChatML structure: description comes from role=system content fragments
            desc = sample.get("description") or sample.get("overview") or ""
            if isinstance(desc, str) and desc:
                stats[cwe]["desc"][desc[:500]] += 1
    print(f"samples scanned: {n}, distinct CWEs hit: {len(stats)}")
    return stats


def merge(stats: dict[str, dict], ref_path: Path) -> list[str]:
    """Merge with the existing cwe_reference.yaml; returns the list of changed CWEs."""
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
                entry["fix_direction"] = f"{entry.get('fix_direction', '')} | dataset-derived: {top_fix[:200]}"
                entry.setdefault("mined_from", []).append(top_fix[:300])
                changed.append(cwe)
        else:
            existing[cwe] = {
                "id": cwe,
                "name": "mined_" + cwe.lower().replace("-", "_"),
                "severity": "medium",
                "description": top_desc or "(dataset-mined, awaiting manual fill)",
                "fix_direction": top_fix or "",
                "mined_from": [top_fix[:300]],
            }
            changed.append(cwe)

    doc = {"cwe": sorted(existing.values(), key=lambda e: e["id"]),
           "_provenance": f"curated baseline + GHSA mining ({datetime.now().isoformat()})"}
    ref_path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return changed


def mine_from_logs(log_dir: Path) -> dict[str, dict]:
    """Mine rule candidates from missed_pattern records in logs/*.jsonl.

    Returns {pattern: {desc: Counter, fix: Counter}} for merging or standalone review.
    """
    stats: dict[str, dict] = defaultdict(lambda: {"desc": Counter(), "fix": Counter()})
    files = list(log_dir.glob("*.jsonl")) if log_dir.is_dir() else []
    n = 0
    for f in files:
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event") != "missed_pattern":
                continue
            n += 1
            pat = rec.get("pattern") or ""
            if not pat:
                continue
            stats[pat]["desc"]["missed_by_validator"] += 1
            stats[pat]["fix"][rec.get("note") or "awaiting manual review"] += 1
    print(f"log-mined missed patterns: {n} records, {len(stats)} distinct patterns")
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description="mine CWE->fix mappings from GHSA/CVE datasets or local logs")
    ap.add_argument("source", nargs="?", help="dataset file or dir (JSONL/JSON); either this or --from-logs")
    ap.add_argument("--out", default=str(PROJECT_ROOT / "rules" / "cwe_reference.yaml"))
    ap.add_argument("--from-logs", action="store_true", help="mine from missed_pattern records in logs/*.jsonl")
    args = ap.parse_args()

    if args.from_logs:
        stats = mine_from_logs(PROJECT_ROOT / "logs")
        if not stats:
            print("no missed_pattern records in logs/ yet. Report missed patterns via cli.py missed first.")
            return 0
        # emit a review list (never written straight into cwe_reference.yaml; the human review gate stays)
        out_path = PROJECT_ROOT / "logs" / "pending_rules.json"
        out_path.write_text(json.dumps(
            {p: {"note": next(iter(s["fix"]), "")} for p, s in stats.items()},
            ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"missed-pattern review list: {out_path}")
        for p, s in stats.items():
            print(f"  - {p[:70]}  ({s['desc']['missed_by_validator']} times)")
        return 0

    src = Path(args.source) if args.source else None
    if not src or not src.exists():
        print(f"data source not found: {src}", file=sys.stderr)
        return 2
    stats = mine(src)
    changed = merge(stats, Path(args.out))
    print(f"updated {args.out}: {len(changed)} CWE(s) added/completed")
    for cwe in changed[:20]:
        print(f"  - {cwe}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
