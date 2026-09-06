# Secure-Vibe Professional Evaluation Guide

This project includes two levels of evaluation: **offline baseline** (runnable immediately) + **paper-grade benchmark** (requires a dataset).

## Offline Baseline (built-in, ready to use)

```bash
# Local benchmark: use the built-in malicious/safe test case set to compute detection rate / false positive rate / latency
python tools/benchmark.py
python tools/run_evaluation.py --local   # equivalent; outputs evaluation_report.json

# Current baseline (29 malicious + 22 safe cases):
#   detection_rate = 1.0, false_positive_rate = 0.0, avg_latency_ms ≈ 0.16
```

## Basic Evaluation (built-in, ready to use)

- `tests/test_validator.py`: per-rule test cases across the three engines (AST + regex + taint)
- `tests/test_repair_loop.py`: repair loop convergence, log completeness, Mock end-to-end
- Self-test: `python cli.py selftest`

## Professional Evaluation (SecurityEval, requires downloading the dataset)

[SecurityEval](https://github.com/s2labres/security-eval) (S2Lab) is the standard evaluation set for secure code
generation, containing malicious code generation samples annotated with CWEs. It is used to measure the validator's
detection rate / false positive rate for this Skill, and to compare against published papers.

### Steps

```bash
# One-shot download of all external datasets (run when network access is available)
python tools/fetch_datasets.py --all --dir D:/datasets
# Or fetch SecurityEval alone
python tools/fetch_datasets.py --securityeval --dir D:/datasets

# Configure config.yaml
evaluation:
  enabled: true
  securityeval_path: "D:/datasets/SecurityEval"

# Run evaluation
python tools/run_evaluation.py
```

### Generic Annotated Corpora (can run even without SecurityEval)

`run_evaluation.py --corpus` accepts any JSONL (each line `{code, insecure, cwe}`) or a source directory:

```bash
python tools/run_evaluation.py --corpus tests/sample_corpus.jsonl   # built-in sample
python tools/run_evaluation.py --corpus D:/datasets/your_data.jsonl # any annotated data
```

Metric definitions are consistent with SecurityEval (detection_rate / false_positive_rate / avg_latency_ms / missed_by_cwe).

### Metric Description

| Metric | Meaning | Target |
|------|------|------|
| `detection_rate` | Detection rate on malicious samples | Higher is better (baseline reference >0.7) |
| `false_positive_rate` | False positive rate on safe samples | Lower is better (<0.05) |
| `repair_success_rate` | Convergence rate of the repair loop within 3 rounds | Higher is better |
| `avg_repair_rounds` | Average number of repair rounds | Lower is better |
| `avg_latency_ms` | Average validation latency | <50ms |

### Missed Detection Analysis

The `missed_by_cwe` field in the evaluation report tallies missed detections by CWE — this is the **direct basis for
rule iteration**: for the CWEs with the most missed detections, add matching patterns to `rules/*.yaml` (you can use
`tools/mine_cwe_rules.py` to mine fixes from the GHSA-CySec dataset), then rerun the evaluation to verify improvement.

### Integration with GHSA-CySec (rule expansion loop)

```bash
# 1. Apply for and download GHSA-CySec from ModelScope (reachable within China)
modelscope download --dataset couvor/GHSA-CySec --local_dir D:\datasets\GHSA-CySec

# 2. Mine CWE → fixes → automatically append rules/cwe_reference.yaml
python tools/mine_cwe_rules.py D:\datasets\GHSA-CySec

# 3. Add detection patterns to rules/*.yaml based on the new knowledge → rerun evaluation
```

## Local Log Mining (offline, the loop is fully available)

No external dataset needed: mine rule candidates directly from runtime missed-detection records (promoted to official
rules after human review):

```bash
# Report a missed pattern (when the Agent finds a pattern the validator did not catch)
python cli.py missed --pattern 'getattr(builtins, "eval")(x)' --note "dynamic builtins access bypass"

# Mine missed patterns → generate review checklist logs/pending_rules.json
python tools/mine_cwe_rules.py --from-logs
```

> Proven in practice: the `getattr(builtins, "eval")` bypass discovered via log mining has been promoted to rule BL-005
> and added to regression tests — this is the minimum viable path of the "reward loop" (find attack → record →
> automatically find a fix → update rules).

## Full Picture of the Iteration Loop

```
missed detections in evaluation (missed_by_cwe) ──┐
manual modification diff (logs) ──────────────────┼─► human review ─► new rules/*.yaml rules ─► rerun evaluation to verify
Agent missed-pattern reports (missed) ────────────┘          (anti-poisoning gate)        │
        ▲                                                                                 │
        └────────────────── continuous loop ◄─────────────────────────────────────────────┘
```
