"""repair_loop.py — 自动修正循环（混合策略）.

流程:
  1. LLM 生成第一版代码
  2. 校验器实时校验
  3. 不通过 → 混合修复:
     a) 高危项: 优先从 templates/ 做确定性替换（不走 LLM，零风险）
        无法确定性替换时 → LLM 修复
     b) 低/中危项: LLM 局部重写（只重写违规片段，非整段重生成）
  4. 最多重试 max_retries 轮；仍失败 → 交付最佳版本 + 完整漏洞报告，
     标记"需人工修复"（needs_human_review=True）
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional

from core.ast_fixer import deterministic_fix
from core.context_builder import build_local_rewrite_prompt, build_prompts, build_repair_prompt
from core.llm_backend import LLMBackend
from core.validator import ValidationResult, Validator, Violation


def _apply_deterministic_fixes(code: str, violations: list[Violation]) -> tuple[str, list[str]]:
    """对可确定性修复的违规做 AST 节点级安全等价改写。

    覆盖: insecure_random / weak_hash / unsafe_yaml_load / hardcoded_secret
    （见 core/ast_fixer.py），返回 (新代码, 已应用的 rule_name 列表)。
    """
    return deterministic_fix(code, violations)


@dataclass
class RepairRound:
    """单轮修复记录。"""
    round_no: int                     # 0 = 首次生成
    code: str
    result: ValidationResult
    action: str = ""                  # generate / deterministic_fix / llm_repair / accepted
    elapsed_ms: float = 0.0


@dataclass
class GenerationOutcome:
    """generate_secure_code 的最终输出。"""
    code: str                         # 最终交付代码
    passed: bool                      # 最终代码是否通过校验
    needs_human_review: bool          # 重试超限仍失败 → True
    rounds: list[RepairRound] = field(default_factory=list)
    report: str = ""                  # 失败时的完整漏洞报告
    total_retries: int = 0
    llm_calls: int = 0
    total_elapsed_ms: float = 0.0

    def summary(self) -> str:
        status = "PASS" if self.passed else ("FAIL(需人工修复)" if self.needs_human_review else "FAIL")
        return (
            f"[{status}] 轮数={len(self.rounds)} 重试={self.total_retries} "
            f"LLM调用={self.llm_calls} 耗时={self.total_elapsed_ms:.0f}ms"
        )


def _extract_code(llm_output: str, language: str = "python") -> str:
    """从 LLM 输出中提取代码块；无代码块时原样返回。"""
    pattern = rf"```(?:{language})?\s*\n(.*?)```"
    m = re.search(pattern, llm_output, re.DOTALL)
    return m.group(1).strip() if m else llm_output.strip()


def _strip_markdown_fence(code: str) -> str:
    """容错：去掉未闭合的围栏标记。"""
    return re.sub(r"^```(?:python)?\s*\n?|```\s*$", "", code).strip()


def _best_round(rounds: list[RepairRound]) -> RepairRound:
    """挑选违规最少的一轮作为兜底交付（重试超限时用）。"""
    if not rounds:
        raise ValueError("rounds 为空")
    return min(rounds, key=lambda r: len(r.result.violations))


def generate_secure_code(
    task_description: str,
    backend: LLMBackend,
    language: str = "python",
    framework: str = "",
    context: str = "",
    validator: Optional[Validator] = None,
    max_retries: int = 3,
    strategy: str = "hybrid",
    rules_dir=None,
    blacklist_dir=None,
    templates_dir=None,
    on_round=None,
) -> GenerationOutcome:
    """核心入口：生成 → 校验 → 混合修复循环。

    参数:
        task_description: 用户任务描述
        backend: LLM 后端（create_backend() 创建）
        language / framework / context: 生成上下文
        validator: 校验器实例（默认按语言新建）
        max_retries: 最大修复轮数
        strategy: hybrid（默认）| llm_only
        on_round: 每轮回调 on_round(RepairRound)，供日志/进度使用
    返回:
        GenerationOutcome
    """
    v = validator or Validator(language=language, rules_dir=rules_dir, blacklist_dir=blacklist_dir)
    t0 = time.perf_counter()
    rounds: list[RepairRound] = []
    llm_calls = 0

    # ---- 第 0 轮：构建安全上下文并生成 ----
    system_prompt, user_prompt = build_prompts(
        task_description, language, framework, context,
        rules_dir=rules_dir, blacklist_dir=blacklist_dir, templates_dir=templates_dir,
    )
    llm_calls += 1
    code = _extract_code(backend.generate(system_prompt, user_prompt), language)
    code = _strip_markdown_fence(code)
    result = v.validate(code)
    r0 = RepairRound(0, code, result, action="generate",
                     elapsed_ms=result.elapsed_ms)
    rounds.append(r0)
    if on_round:
        on_round(r0)

    # ---- 修复循环 ----
    retries = 0
    while not result.passed and retries < max_retries:
        retries += 1

        # a) 确定性修复（仅 hybrid 策略，毫秒级零风险）
        if strategy == "hybrid":
            fixed_code, fixed_rules = _apply_deterministic_fixes(code, result.violations)
            if fixed_rules and fixed_code != code:
                code = fixed_code
                result = v.validate(code)
                rd = RepairRound(retries, code, result, action="deterministic_fix",
                                 elapsed_ms=result.elapsed_ms)
                rounds.append(rd)
                if on_round:
                    on_round(rd)
                if result.passed:
                    break

        # b) LLM 修复（混合策略下仅当确定性修复未解决时）
        high = result.has_high
        if strategy == "hybrid" and not high:
            # 低/中危 → 局部重写 prompt
            vlines = "\n".join(
                f"- 第{vl.line}行 [{vl.rule_id}] {vl.message} → {vl.fix_hint}"
                for vl in result.violations
            )
            repair_prompt = build_local_rewrite_prompt(code, vlines, language)
        else:
            # 高危或 llm_only → 完整修复 prompt
            repair_prompt = build_repair_prompt(code, result.summary(), language)

        llm_calls += 1
        code = _extract_code(backend.generate(system_prompt, repair_prompt), language)
        code = _strip_markdown_fence(code)
        result = v.validate(code)
        rd = RepairRound(retries, code, result, action="llm_repair",
                         elapsed_ms=result.elapsed_ms)
        rounds.append(rd)
        if on_round:
            on_round(rd)

    # ---- 收尾 ----
    total_ms = (time.perf_counter() - t0) * 1000
    if result.passed:
        return GenerationOutcome(
            code=code, passed=True, needs_human_review=False,
            rounds=rounds, total_retries=retries, llm_calls=llm_calls,
            total_elapsed_ms=total_ms,
        )

    # 重试超限：交付违规最少的一轮 + 完整漏洞报告
    best = _best_round(rounds)
    report_lines = [
        "# Secure-Vibe 漏洞报告（需人工修复）",
        f"任务: {task_description}",
        f"语言: {language}" + (f" 框架: {framework}" if framework else ""),
        f"重试轮数: {retries}/{max_retries}",
        "",
        best.result.summary(),
        "",
        "## 交付代码（最佳版本，仍含未修复违规）",
        f"```{language}",
        best.code,
        "```",
    ]
    return GenerationOutcome(
        code=best.code, passed=False, needs_human_review=True,
        rounds=rounds, report="\n".join(report_lines),
        total_retries=retries, llm_calls=llm_calls, total_elapsed_ms=total_ms,
    )
