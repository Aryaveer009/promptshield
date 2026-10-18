"""Scan orchestration: send each attack, run detectors, optionally judge, build the result."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime

from promptshield import __version__
from promptshield.adapters.base import TargetAdapter, TargetError
from promptshield.branding import AUTHOR_NAME, AUTHOR_URL
from promptshield.detectors import DetectionContext, evaluate
from promptshield.judge import JUDGE_DISCLAIMER, LLMJudge
from promptshield.models import (
    Attack,
    Finding,
    ScanResult,
    TargetInfo,
    TargetRequest,
    Verdict,
)
from promptshield.scoring import category_scores, grade_for, owasp_scores, weighted_score

ProgressCallback = Callable[[int, int, Finding], None]


def run_attack(
    adapter: TargetAdapter,
    attack: Attack,
    ctx: DetectionContext,
    judge: LLMJudge | None = None,
) -> Finding:
    request = TargetRequest(message=attack.prompt, documents=list(attack.documents))
    started = time.perf_counter()
    try:
        response = adapter.send(request)
    except TargetError as exc:
        return Finding(
            attack=attack,
            verdict=Verdict.ERROR,
            request=request,
            error=str(exc),
            latency_ms=int((time.perf_counter() - started) * 1000),
        )
    latency_ms = int((time.perf_counter() - started) * 1000)

    evaluation = evaluate(attack, response, ctx)
    if not evaluation.evaluable:
        return Finding(
            attack=attack,
            verdict=Verdict.SKIPPED,
            request=request,
            response=response,
            skipped_reason=evaluation.skipped_reason,
            latency_ms=latency_ms,
        )

    verdict = Verdict.FAIL if evaluation.hits else Verdict.PASS
    finding = Finding(
        attack=attack,
        verdict=verdict,
        request=request,
        response=response,
        hits=evaluation.hits,
        latency_ms=latency_ms,
    )
    # The judge only reviews attacks the detectors passed (so the planted canary is never
    # forwarded to a third-party judge unless a detector missed an obfuscated leak).
    if judge is not None and verdict is Verdict.PASS:
        finding.judge = judge.judge(attack, response)
    return finding


def run_scan(
    adapter: TargetAdapter,
    attacks: list[Attack],
    ctx: DetectionContext,
    *,
    judge: LLMJudge | None = None,
    delay_s: float = 0.0,
    on_progress: ProgressCallback | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Finding]:
    findings: list[Finding] = []
    for index, attack in enumerate(attacks, start=1):
        finding = run_attack(adapter, attack, ctx, judge)
        findings.append(finding)
        if on_progress:
            on_progress(index, len(attacks), finding)
        if delay_s and index < len(attacks):
            sleep(delay_s)
    return findings


def build_result(
    *,
    findings: list[Finding],
    adapter: TargetAdapter,
    target_type: str,
    attestation: str,
    started_at: datetime,
    judge: LLMJudge | None = None,
    notes: list[str] | None = None,
) -> ScanResult:
    passed = sum(f.verdict is Verdict.PASS for f in findings)
    failed = sum(f.verdict is Verdict.FAIL for f in findings)
    errors = sum(f.verdict is Verdict.ERROR for f in findings)
    skipped = sum(f.verdict is Verdict.SKIPPED for f in findings)
    score = weighted_score(findings)
    flagged = sum(1 for f in findings if f.judge and f.judge.label == "suspicious")

    all_notes = list(notes or [])
    if judge is not None:
        all_notes.append(JUDGE_DISCLAIMER)
    if errors:
        all_notes.append(f"{errors} attack(s) errored and are excluded from the score.")
    if skipped:
        all_notes.append(
            f"{skipped} attack(s) were skipped (no usable ground truth) and are excluded from the score."
        )

    return ScanResult(
        version=__version__,
        author=AUTHOR_NAME,
        author_url=AUTHOR_URL,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        target=TargetInfo(type=target_type, name=adapter.name, description=adapter.describe()),
        attestation=attestation,
        score=score,
        grade=grade_for(score),
        total=len(findings),
        passed=passed,
        failed=failed,
        errors=errors,
        skipped=skipped,
        categories=category_scores(findings),
        owasp=owasp_scores(findings),
        findings=findings,
        judge_enabled=judge is not None,
        judge_model=judge.model if judge else None,
        judge_flagged=flagged,
        notes=all_notes,
    )
