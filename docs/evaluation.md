# Secure-Vibe 专业级评测指南

本项目内置两种评测级别：

## 基础评测（内置，开箱即用）

- `tests/test_validator.py`：69 个用例（恶意检出 + 安全零误报），`python -m pytest tests/ -q`
- `tests/test_repair_loop.py`：修复循环收敛、日志完整性、Mock 端到端
- 自检：`python cli.py selftest`

## 专业级评测（SecurityEval，需下载数据集）

[SecurityEval](https://github.com/s2labres/security-eval)（S2Lab）是安全代码生成领域的标准评测集，
含 CWE 标注的恶意代码生成样本。用于测量本 Skill 校验器的检出率/误报率，可与论文对比。

### 步骤

```bash
# 1. 下载数据集（国内需代理，或从镜像获取）
git clone https://github.com/s2labres/security-eval.git D:\datasets\SecurityEval

# 2. 配置 config.yaml
evaluation:
  enabled: true
  securityeval_path: "D:/datasets/SecurityEval"

# 3. 运行评测
python tools/run_evaluation.py
```

### 指标说明

| 指标 | 含义 | 目标 |
|------|------|------|
| `detection_rate` | 恶意样本检出率 | 越高越好（基线参考 >0.7） |
| `false_positive_rate` | 安全样本误报率 | 越低越好（<0.05） |
| `repair_success_rate` | 修复循环 3 轮内收敛率 | 越高越好 |
| `avg_repair_rounds` | 平均修复轮数 | 越低越好 |
| `avg_latency_ms` | 平均校验耗时 | <50ms |

### 漏检分析

评测报告 `missed_by_cwe` 字段按 CWE 统计漏检——这是**规则迭代的直接依据**：
对漏检最多的 CWE，在 `rules/*.yaml` 中补充对应模式（可用 `tools/mine_cwe_rules.py`
从 GHSA-CySec 数据集挖掘修复措施），然后重跑评测验证提升。

### 与 GHSA-CySec 联动（规则扩充闭环）

```bash
# 1. ModelScope 申请并下载 GHSA-CySec（国内可达）
modelscope download --dataset couvor/GHSA-CySec --local_dir D:\datasets\GHSA-CySec

# 2. 挖掘 CWE→修复措施 → 自动补充 rules/cwe_reference.yaml
python tools/mine_cwe_rules.py D:\datasets\GHSA-CySec

# 3. 依据新知识补充 rules/*.yaml 检测模式 → 重跑评测
```

## 迭代闭环全景

```
评测漏检（missed_by_cwe）──┐
人工修改 diff（日志）──────┼─► 人工审核 ─► rules/*.yaml 新规则 ─► 重跑评测验证
Agent 漏检上报（missed）──┘         （防投毒闸口）        │
        ▲                                              │
        └──────────────── 持续循环 ◄───────────────────┘
```
