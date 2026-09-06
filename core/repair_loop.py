"""repair_loop.py — Automatic repair loop (hybrid strategy).

Flow:
  1. The LLM generates the first version of the code
  2. The validator checks it in real time
  3. On failure -> hybrid repair:
     a) high-risk items: deterministic replacement from templates/ first (no LLM, zero risk);
        when deterministic replacement is impossible -> LLM repair
     b) low/medium items: LLM local rewrite (only the violating fragment, not a full regeneration)
  4. Retry at most max_retries rounds; on repeated failure -> deliver the best version + a full
     vulnerability report, marked "needs human review" (needs_human_review=True)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from core.ast_fixer import deterministic_fix
from core.context_builder import build_local_rewrite_prompt, build_prompts, build_repair_prompt
from core.llm_backend import LLMBackend
from core.validator import ValidationResult, Validator, Violation


def _apply_deterministic_fixes(code: str, violations: list[Violation]) -> tuple[str, list[str]]:
    """Apply AST-node-level safe equivalent rewrites for deterministically fixable violations.

    Coverage: insecure_random / weak_hash / unsafe_yaml_load / hardcoded_secret
    (see core/ast_fixer.py). Returns (new code, list of applied rule_names).
    """
    return deterministic_fix(code, violations)


@dataclass
class RepairRound:
    """One repair round record."""
    round_no: int                     # 0 = first generation
    code: str
    result: ValidationResult
    action: str = ""                  # generate / deterministic_fix / llm_repair / accepted
    elapsed_ms: float = 0.0


@dataclass
class GenerationOutcome:
    """Final output of generate_secure_code."""
    code: str                         # final delivered code
    passed: bool                      # whether the final code passed validation
    needs_human_review: bool          # True when retries were exhausted and still failing
    rounds: list[RepairRound] = field(default_factory=list)
    report: str = ""                  # full vulnerability report on failure
    total_retries: int = 0
    llm_calls: int = 0
    total_elapsed_ms: float = 0.0
    review_ticket: str = ""           # path to the human-review markdown file (when written)
    regression: Optional[dict] = None  # post-repair regression verification result

    def summary(self) -> str:
        status = "PASS" if self.passed else ("FAIL(needs human review)" if self.needs_human_review else "FAIL")
        return (
            f"[{status}] rounds={len(self.rounds)} retries={self.total_retries} "
            f"llm_calls={self.llm_calls} elapsed={self.total_elapsed_ms:.0f}ms"
        )


def _extract_code(llm_output: str, language: str = "python") -> str:
    """Extract the code block from LLM output; return as-is when none."""
    pattern = rf"```(?:{language})?\s*\n(.*?)```"
    m = re.search(pattern, llm_output, re.DOTALL)
    return m.group(1).strip() if m else llm_output.strip()


def _strip_markdown_fence(code: str) -> str:
    """Tolerance: strip unclosed fence markers."""
    return re.sub(r"^```(?:python)?\s*\n?|```\s*$", "", code).strip()


def _best_round(rounds: list[RepairRound]) -> RepairRound:
    """Pick the round with the fewest violations as the fallback delivery (retries exhausted)."""
    if not rounds:
        raise ValueError("rounds is empty")
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
    regression_check: Optional[Callable[[str], Optional[bool]]] = None,
    review_dir=None,
) -> GenerationOutcome:
    """Core entry point: generate -> validate -> hybrid repair loop.

    Args:
        task_description: the user task description
        backend: LLM backend (created via create_backend())
        language / framework / context: generation context
        validator: validator instance (built per language by default)
        max_retries: maximum repair rounds
        strategy: hybrid (default) | llm_only
        on_round: per-round callback on_round(RepairRound), for logging/progress
        regression_check: optional callable(code) -> True/False/None. Called when a
            repair first passes the lint; False = the project's tests fail with the
            repaired code = the repair is reverted (a passing lint that breaks
            behavior is a failed repair). None = regression verification disabled.
        review_dir: optional directory; when retries are exhausted a full human-review
            markdown ticket (context + alternatives) is written there.
    Returns:
        GenerationOutcome
    """
    v = validator or Validator(language=language, rules_dir=rules_dir, blacklist_dir=blacklist_dir)
    t0 = time.perf_counter()
    rounds: list[RepairRound] = []
    llm_calls = 0

    # ---- round 0: build the security context and generate ----
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

    # ---- repair loop ----
    retries = 0
    regression_ran = False
    regression_verdict: Optional[bool] = None
    while not result.passed and retries < max_retries:
        retries += 1

        # a) deterministic fix (hybrid strategy only; millisecond-scale, zero risk)
        if strategy == "hybrid":
            fixed_code, fixed_rules = _apply_deterministic_fixes(code, result.violations)
            if fixed_rules and fixed_code != code:
                new_result = v.validate(fixed_code)
                if new_result.passed and regression_check is not None:
                    verdict = regression_check(fixed_code)
                    if verdict is False:
                        # the fix broke behavior: revert, keep the loop going
                        rd = RepairRound(retries, fixed_code, new_result,
                                         action="deterministic_fix; reverted (regression failed)",
                                         elapsed_ms=new_result.elapsed_ms)
                        rounds.append(rd)
                        if on_round:
                            on_round(rd)
                        regression_ran = True
                        regression_verdict = False
                        continue
                    regression_ran = regression_ran or (verdict is True)
                    regression_verdict = verdict if verdict is True else regression_verdict
                code, result = fixed_code, new_result
                rd = RepairRound(retries, code, result, action="deterministic_fix",
                                 elapsed_ms=result.elapsed_ms)
                rounds.append(rd)
                if on_round:
                    on_round(rd)
                if result.passed:
                    break

        # b) LLM repair (hybrid strategy: only when deterministic fix did not resolve)
        high = result.has_high
        if strategy == "hybrid" and not high:
            # low/medium -> local rewrite prompt
            vlines = "\n".join(
                f"- line {vl.line} [{vl.rule_id}] {vl.message} -> {vl.fix_hint}"
                for vl in result.violations
            )
            repair_prompt = build_local_rewrite_prompt(code, vlines, language)
        else:
            # high severity or llm_only -> full repair prompt
            repair_prompt = build_repair_prompt(code, result.summary(), language)

        llm_calls += 1
        new_code = _extract_code(backend.generate(system_prompt, repair_prompt), language)
        new_code = _strip_markdown_fence(new_code)
        new_result = v.validate(new_code)
        if new_result.passed and regression_check is not None and not result.passed:
            verdict = regression_check(new_code)
            if verdict is False:
                # the LLM fix broke behavior: revert to the pre-repair state
                rd = RepairRound(retries, new_code, new_result,
                                 action="llm_repair; reverted (regression failed)",
                                 elapsed_ms=new_result.elapsed_ms)
                rounds.append(rd)
                if on_round:
                    on_round(rd)
                regression_ran = True
                regression_verdict = False
                continue
            regression_ran = True
            regression_verdict = verdict if verdict is True else regression_verdict
        code, result = new_code, new_result
        rd = RepairRound(retries, code, result, action="llm_repair",
                         elapsed_ms=result.elapsed_ms)
        rounds.append(rd)
        if on_round:
            on_round(rd)

    # ---- wrap-up ----
    total_ms = (time.perf_counter() - t0) * 1000
    regression_dict = (
        {"ran": regression_ran, "passed": regression_verdict}
        if regression_check is not None else None
    )
    if result.passed:
        return GenerationOutcome(
            code=code, passed=True, needs_human_review=False,
            rounds=rounds, total_retries=retries, llm_calls=llm_calls,
            total_elapsed_ms=total_ms, regression=regression_dict,
        )

    # retries exhausted: deliver the round with the fewest violations + a full review ticket
    best = _best_round(rounds)
    ticket = _build_review_ticket(
        task_description, language, framework, max_retries, retries, best, rounds,
    )
    ticket_path = ""
    if review_dir is not None:
        from pathlib import Path as _P
        rd = _P(review_dir)
        rd.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^\w\-]+", "-", task_description)[:40].strip("-") or "task"
        p = rd / f"review-{stamp}-{safe}.md"
        p.write_text(ticket, encoding="utf-8")
        ticket_path = str(p)
    return GenerationOutcome(
        code=best.code, passed=False, needs_human_review=True,
        rounds=rounds, report=ticket, total_retries=retries, llm_calls=llm_calls,
        total_elapsed_ms=total_ms, review_ticket=ticket_path,
        regression=regression_dict,
    )


def _build_review_ticket(
    task_description: str,
    language: str,
    framework: str,
    max_retries: int,
    retries: int,
    best: "RepairRound",
    rounds: list["RepairRound"],
) -> str:
    """Full human-review markdown: context, per-violation analysis, alternatives, next steps."""
    lines = [
        "# Secure-Vibe human review ticket",
        "",
        f"**Task**: {task_description}",
        f"**Language**: {language}" + (f"  **Framework**: {framework}" if framework else ""),
        f"**Retries**: {retries}/{max_retries} — the repair loop did not converge",
        "",
    ]

    # regression status
    reverted = [r for r in rounds if "reverted" in r.action]
    if reverted:
        lines += [
            "## Regression verification",
            "",
            f"{len(reverted)} repair round(s) passed the lint but broke behavior "
            f"(regression check failed) and were reverted:",
            "",
        ]
        lines += [f"- round {r.round_no}: {r.action}" for r in reverted]
        lines.append("")

    lines += [best.result.summary(), ""]

    # per-violation analysis with alternatives
    lines += ["## Unfixed violations (with alternatives)", ""]
    templates: list[str] = []
    cwes: list[str] = []
    for viol in best.result.violations:
        lines.append(f"### {viol.rule_id} — line {viol.line} [{viol.severity}]")
        lines.append(f"- **what**: {viol.message}")
        lines.append(f"- **how to fix**: {viol.fix_hint}")
        if viol.cwe:
            cwes.append(viol.cwe)
        if viol.template:
            templates.append(viol.template)
            lines.append(f"- **reference implementation**: `templates/{language}/{viol.template}` "
                         f"(run `python cli.py context --task \"{task_description}\" --language {language} --full` "
                         f"to see it inline)")
        if viol.cwe:
            lines.append(f"- **background**: `python cli.py cwe --id {viol.cwe}`")
        lines.append(f"- **code at line {viol.line}**: `{viol.snippet}`")
        lines.append("")

    # alternatives & next steps
    lines += ["## Alternatives & next steps", ""]
    if templates:
        seen = []
        for t in templates:
            if t not in seen:
                seen.append(t)
        lines.append("1. Start from the safe reference templates listed above and adapt them, "
                     "instead of patching the generated code further.")
    lines.append("1. Split the task: fix one violation per prompt round and re-validate between steps.")
    lines.append("1. If the violations conflict (e.g. the framework requires the flagged API), "
                 "document why and add the rule ID to `--ignore` for this file only, "
                 "then report the pattern via `python cli.py missed` so the rule can be refined.")
    lines.append("1. Re-run `python cli.py validate --file <file>` after each change.")
    lines.append("")
    lines += [
        "## Delivered code (best version, still contains unfixed violations)",
        f"```{language}",
        best.code,
        "```",
        "",
        "## Round history",
        "",
    ]
    for r in rounds:
        lines.append(f"- round {r.round_no} [{r.action}]: {len(r.result.violations)} violation(s), "
                     f"{r.result.summary()}")
    return "\n".join(lines)
