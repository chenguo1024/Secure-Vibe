"""benchmark.py — Local security benchmark (offline, no external datasets).

Purpose:
  - evaluate live from the built-in malicious/safe case sets (sourced from tests/test_validator.py):
      detection_rate        malicious-sample detection rate (per rule)
        false_positive_rate   safe-sample false-positive rate
        avg_latency_ms        average validation latency
  - write results to logs/benchmark_report.json (comparable with later SecurityEval reports)

Usage:
    python tools/benchmark.py                  # run with default config
    python tools/benchmark.py --fast           # only the first 20 cases (smoke)

Relation:
  - built-in cases = offline baseline; SecurityEval = paper-grade benchmark (tools/run_evaluation.py)
  - metric definitions stay aligned for comparison
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from core.validator import Validator  # noqa: E402
from test_validator import MALICIOUS_CASES, SAFE_CASES  # noqa: E402


def run_benchmark(language: str = "python", limit: int = 0) -> dict:
    v = Validator(language=language)
    malicious = MALICIOUS_CASES[:limit] if limit else MALICIOUS_CASES
    safe = SAFE_CASES[:limit] if limit else SAFE_CASES

    detected = 0
    missed_by_rule: dict[str, list[str]] = defaultdict(list)
    per_rule_total: dict[str, int] = defaultdict(int)
    per_rule_detected: dict[str, int] = defaultdict(int)
    lat_ms: list[float] = []

    for rule_id, code in malicious:
        per_rule_total[rule_id] += 1
        r = v.validate(code)
        lat_ms.append(r.elapsed_ms)
        if not r.passed:
            detected += 1
            per_rule_detected[rule_id] += 1
        else:
            missed_by_rule[rule_id].append(code[:80])

    false_pos = 0
    fp_examples: list[str] = []
    for code in safe:
        r = v.validate(code)
        lat_ms.append(r.elapsed_ms)
        if not r.passed:
            false_pos += 1
            fp_examples.append({"code": code[:80], "violations": [x.rule_id for x in r.violations]})

    n_m = len(malicious)
    n_s = len(safe)
    report = {
        "benchmark": "local_builtin",
        "source": "tests/test_validator.py (hand-curated case sets)",
        "malicious_samples": n_m,
        "safe_samples": n_s,
        "detection_rate": round(detected / n_m, 4) if n_m else None,
        "false_positive_rate": round(false_pos / n_s, 4) if n_s else None,
        "avg_latency_ms": round(sum(lat_ms) / len(lat_ms), 3) if lat_ms else 0,
        "max_latency_ms": round(max(lat_ms), 3) if lat_ms else 0,
        "per_rule": {
            rid: {
                "total": per_rule_total[rid],
                "detected": per_rule_detected[rid],
                "rate": round(per_rule_detected[rid] / per_rule_total[rid], 4),
            }
            for rid in sorted(per_rule_total)
        },
        "missed_by_rule": {rid: codes for rid, codes in sorted(missed_by_rule.items())},
        "false_positive_examples": fp_examples,
    }
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Secure-Vibe local benchmark")
    ap.add_argument("--fast", action="store_true", help="only run the first 20 cases (smoke)")
    args = ap.parse_args()

    limit = 20 if args.fast else 0
    report = run_benchmark(limit=limit)
    out = ROOT / "logs" / "benchmark_report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps(report, ensure_ascii=False, indent=1))
    print(f"\nreport written to: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
