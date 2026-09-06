"""run_evaluation.py — Pro-level evaluation (SecurityEval dataset, optional).

Prerequisites:
  1. download the SecurityEval dataset (from GitHub, use a proxy):
     # or download via mirror/proxy and set config.yaml -> evaluation.securityeval_path
  2. config.yaml: evaluation.enabled: true + securityeval_path: <path>
  2. config.yaml: evaluation.enabled: true + securityeval_path: <path>

Usage:
    python tools/run_evaluation.py                # read config.yaml
      python tools/run_evaluation.py --path <dataset path>

Metrics (config.yaml -> evaluation.metrics):
      - detection_rate       malicious-sample detection rate
      - false_positive_rate  safe-sample false-positive rate
      - avg_latency_ms       average validation latency
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yaml
    from core.validator import Validator
except ImportError as exc:
    print(f"missing dependency: {exc}", file=sys.stderr)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_eval_config() -> dict:
    p = PROJECT_ROOT / "config.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {} if p.is_file() else {}
    return (cfg.get("evaluation", {}) or {})


def load_securityeval_samples(dataset_path: Path):
    """Parse a SecurityEval directory.

    SecurityEval structure: Id_<CWE> dirs / Pareto Properties/*.json (insecure prompt + eval)
    Sample format:
      - JSONL: {"id", "prompt"/"code", "insecure"(bool), "cwe"}
    - directories: same as samples/*.json
    """
    samples = []
    if dataset_path.is_file():
        files = [dataset_path]
    else:
        files = [p for p in dataset_path.rglob("*") if p.suffix in (".json", ".jsonl", ".py")]
    for f in sorted(files):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        items = []
        if f.suffix == ".jsonl":
            items = [json.loads(l) for l in text.splitlines() if l.strip().startswith("{")]
        else:
            try:
                data = json.loads(text)
                items = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                continue
        for item in items:
            if not isinstance(item, dict):
                continue
            code = item.get("code") or item.get("completion") or item.get("output") or ""
            if not code:
                continue
            insecure = item.get("insecure")
            if insecure is None:
                insecure = True
            cwe = item.get("cwe") or ""
            samples.append({"code": code, "insecure": bool(insecure), "cwe": cwe, "source": str(f)})

        # fallback: directories containing only unlabeled .py sources -> treat all as "malicious" (insecure=True) to keep the metric definition consistent
    if not samples:
        for f in sorted(dataset_path.rglob("*.py")):
            try:
                code = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if code.strip():
                samples.append({"code": code, "insecure": True, "cwe": "", "source": str(f)})
    return samples


def evaluate(samples, language: str = "python") -> dict:
    v = Validator(language=language)
    detected = 0
    false_pos = 0
    total_ms = 0.0
    missed_cwe = {}

    for s in samples:
        r = v.validate(s["code"])
        total_ms += r.elapsed_ms
        if s["insecure"]:
            if not r.passed:
                detected += 1
            else:
                missed_cwe[s["cwe"] or "unknown"] = missed_cwe.get(s["cwe"] or "unknown", 0) + 1
        else:
            if r.passed:
                pass
            else:
                false_pos += 1

    insecure_n = sum(1 for s in samples if s["insecure"])
    safe_n = len(samples) - insecure_n
    return {
        "source": "SecurityEval (authoritative benchmark)",
        "total_samples": len(samples),
        "insecure_samples": insecure_n,
        "safe_samples": safe_n,
        "detection_rate": round(detected / insecure_n, 4) if insecure_n else None,
        "false_positive_rate": round(false_pos / safe_n, 4) if safe_n else None,
        "avg_latency_ms": round(total_ms / len(samples), 3) if samples else 0,
        "missed_by_cwe": dict(sorted(missed_cwe.items(), key=lambda kv: -kv[1])),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Secure-Vibe pro-level evaluation (SecurityEval)")
    ap.add_argument("--path", default="", help="SecurityEval dataset path (defaults to config.yaml)")
    ap.add_argument("--local", action="store_true", help="offline baseline on built-in samples (no external dataset)")
    ap.add_argument("--corpus", default="", help="alternate dataset file/dir (jsonl or python corpus dir)")
    args = ap.parse_args()

    if args.local:
        sys.path.insert(0, str(PROJECT_ROOT / "tools"))
        import benchmark
        report = benchmark.run_benchmark(limit=0)
        report["source"] = "local builtin benchmark (自测小样本, not an authoritative external benchmark)"
        out = PROJECT_ROOT / "logs" / "evaluation_report.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=1))
        print(f"\noffline benchmark report written to: {out}")
        return 0

    if args.corpus:
        samples = load_securityeval_samples(Path(args.corpus))
        if not samples:
            print("cannot run corpus evaluation: check the path/format -> docs/evaluation.md", file=sys.stderr)
            return 2
        result = evaluate(samples)
        out = PROJECT_ROOT / "logs" / "evaluation_report.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=1))
        print(f"\nreport written to: {out}")
        return 0

    cfg = load_eval_config()
    path = args.path or cfg.get("securityeval_path", "")
    if not path or not Path(path).is_dir():
        print("no SecurityEval dataset path configured, usage:\n"
              "  offline: python tools/run_evaluation.py --local\n"
              "  corpus: python tools/run_evaluation.py --corpus <jsonl or dir>\n"
          "  benchmark:\n"
          "    1. download SecurityEval locally\n"
          "    2. config.yaml: evaluation.securityeval_path: <path>\n"
          "    3. re-run this script", file=sys.stderr)
        return 2

    samples = load_securityeval_samples(Path(path))
    if not samples:
        print("dataset entry points not found; check the top structure/format -> docs/evaluation.md", file=sys.stderr)
        return 2

    result = evaluate(samples)
    out = PROJECT_ROOT / "logs" / "evaluation_report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=1))
    print(f"\nreport written to: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
