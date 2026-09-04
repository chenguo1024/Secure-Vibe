"""run_evaluation.py — 专业级评测（SecurityEval 数据集，可选）.

前置条件:
  1. 下载 SecurityEval 数据集（网络需可达 GitHub 或使用代理）:
     git clone https://github.com/s2labres/security-eval.git <路径>
     # 国内可用镜像/代理，或手动下载后配置 config.yaml → evaluation.securityeval_path
  2. config.yaml: evaluation.enabled: true + securityeval_path: <路径>

用法:
    python tools/run_evaluation.py                # 按 config.yaml 配置运行
    python tools/run_evaluation.py --path <数据集路径>

指标（config.yaml → evaluation.metrics）:
    - detection_rate       恶意样本检出率
    - false_positive_rate  安全样本误报率
    - avg_latency_ms       平均校验耗时
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
    print(f"缺少依赖: {exc}", file=sys.stderr)
    sys.exit(2)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_eval_config() -> dict:
    p = PROJECT_ROOT / "config.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {} if p.is_file() else {}
    return (cfg.get("evaluation", {}) or {})


def load_securityeval_samples(dataset_path: Path):
    """加载 SecurityEval 样本。

    SecurityEval 结构: Id_<CWE> 目录下Pareto Properties/*.json（insecure prompt + eval）
    兼容格式:
      - JSONL: {"id", "prompt"/"code", "insecure"(bool), "cwe"}
      - 目录: samples/*.json 同上
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

    # 兜底：目录里只有 .py 源码且无标注 → 全部视为"待检测"(insecure=True)做检出率统计
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
        "total_samples": len(samples),
        "insecure_samples": insecure_n,
        "safe_samples": safe_n,
        "detection_rate": round(detected / insecure_n, 4) if insecure_n else None,
        "false_positive_rate": round(false_pos / safe_n, 4) if safe_n else None,
        "avg_latency_ms": round(total_ms / len(samples), 3) if samples else 0,
        "missed_by_cwe": dict(sorted(missed_cwe.items(), key=lambda kv: -kv[1])),
    } 


def main() -> int:
    ap = argparse.ArgumentParser(description="Secure-Vibe 专业级评测（SecurityEval）")
    ap.add_argument("--path", default="", help="SecurityEval 数据集路径（覆盖 config.yaml）")
    ap.add_argument("--local", action="store_true", help="使用内置用例集跑离线基准（无需外部数据集）")
    ap.add_argument("--corpus", default="", help="通用标注语料：JSONL 每行 {code,insecure,cwe}，或目录递归扫描")
    args = ap.parse_args()

    if args.local:
        import benchmark
        report = benchmark.run_benchmark(limit=0)
        report["benchmark"] = "local_builtin"
        out = PROJECT_ROOT / "logs" / "evaluation_report.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=1))
        print(f"\n离线基准报告已写入: {out}")
        return 0

    if args.corpus:
        samples = load_securityeval_samples(Path(args.corpus))
        if not samples:
            print("未能从语料解析样本，格式要求见 docs/evaluation.md", file=sys.stderr)
            return 2
        result = evaluate(samples)
        out = PROJECT_ROOT / "logs" / "evaluation_report.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=1))
        print(f"\n报告已写入: {out}")
        return 0

    cfg = load_eval_config()
    path = args.path or cfg.get("securityeval_path", "")
    if not path or not Path(path).is_dir():
        print("未配置 SecurityEval 数据集路径。两步方案：\n"
              "  离线基线: python tools/run_evaluation.py --local\n"
              "  通用语料: python tools/run_evaluation.py --corpus <jsonl或目录>\n"
              "  论文级评测:\n"
              "    1. python tools/fetch_datasets.py --securityeval --dir D:/datasets\n"
              "    2. config.yaml: evaluation.securityeval_path: <路径>\n"
              "    3. 重新运行本脚本", file=sys.stderr)
        return 2

    samples = load_securityeval_samples(Path(path))
    if not samples:
        print("未从数据集解析出样本，请检查数据集格式（见 docs/evaluation.md）", file=sys.stderr)
        return 2

    result = evaluate(samples)
    out = PROJECT_ROOT / "logs" / "evaluation_report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=1))
    print(f"\n报告已写入: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
