"""benchmark.py — 本地安全基准评测（离线，无需外部数据集）.

用途:
  - 用内置恶意/安全用例集（源自 tests/test_validator.py）实时计算:
      detection_rate        恶意样本检出率（按规则逐项）
      false_positive_rate   安全样本误报率
      avg_latency_ms        平均校验耗时
  - 将结果写入 logs/benchmark_report.json（可与后续 SecurityEval 报告对比）

用法:
    python tools/benchmark.py                  # 默认配置运行
    python tools/benchmark.py --fast           # 只跑前 20 个用例（冒烟）

关系:
  - 内置用例 = 离线基线；SecurityEval = 论文级基准（tools/run_evaluation.py）
  - 两者指标口径一致，便于对比
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
        "source": "tests/test_validator.py (手构用例集)",
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
    ap = argparse.ArgumentParser(description="Secure-Vibe 本地基准评测")
    ap.add_argument("--fast", action="store_true", help="只跑前 20 个用例（冒烟）")
    args = ap.parse_args()

    limit = 20 if args.fast else 0
    report = run_benchmark(limit=limit)
    out = ROOT / "logs" / "benchmark_report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps(report, ensure_ascii=False, indent=1))
    print(f"\n报告已写入: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
