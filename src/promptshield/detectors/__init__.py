"""Deterministic detection: the primary, reliable way PromptShield decides pass/fail."""

from __future__ import annotations

from dataclasses import dataclass, field

from promptshield.detectors.base import DetectionContext, Detector
from promptshield.detectors.checks import (
    CanaryDetector,
    MarkerDetector,
    PromptLeakDetector,
    RegexDetector,
    ToolCallDetector,
    UnsafeOutputDetector,
)
from promptshield.models import Attack, DetectorHit, TargetResponse

DETECTORS: dict[str, Detector] = {
    d.spec_type: d
    for d in (
        CanaryDetector(),
        MarkerDetector(),
        RegexDetector(),
        PromptLeakDetector(),
        UnsafeOutputDetector(),
        ToolCallDetector(),
    )
}


@dataclass
class Evaluation:
    hits: list[DetectorHit] = field(default_factory=list)
    evaluable: bool = True
    skipped_reason: str | None = None


def evaluate(attack: Attack, response: TargetResponse, ctx: DetectionContext) -> Evaluation:
    """Run every detector of ``attack``. Any hit means the attack succeeded.

    If *none* of the attack's detectors can be evaluated (for example a canary attack with no
    canary configured) the attack is reported as skipped rather than silently passed.
    """
    hits: list[DetectorHit] = []
    evaluated = 0
    missing: list[str] = []
    for spec in attack.detectors:
        detector = DETECTORS[spec.type]
        if not detector.is_evaluable(spec, ctx):
            missing.append(spec.type)
            continue
        evaluated += 1
        hit = detector.check(spec, response, ctx)
        if hit:
            hits.append(hit)
    if evaluated == 0:
        return Evaluation(
            evaluable=False,
            skipped_reason=(
                "No detector could run: missing ground truth for "
                + ", ".join(sorted(missing))
                + ". "
                "Configure `canary` / `system_prompt` in promptshield.yaml."
            ),
        )
    return Evaluation(hits=hits)


__all__ = ["DETECTORS", "DetectionContext", "Detector", "Evaluation", "evaluate"]
