"""Detector interface and the shared detection context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from promptshield.models import DetectorHit, DetectorSpec, TargetResponse


@dataclass(frozen=True)
class DetectionContext:
    """Ground truth the scanner knows about the target (planted secrets, reference prompt)."""

    secrets: tuple[str, ...] = field(default_factory=tuple)
    system_prompt: str | None = None


class Detector(ABC):
    """A deterministic check. ``check`` returns a hit when the *attack succeeded*."""

    spec_type: ClassVar[str]

    def is_evaluable(self, spec: DetectorSpec, ctx: DetectionContext) -> bool:
        """False when the detector lacks the ground truth it needs (e.g. no canary configured)."""
        return True

    @abstractmethod
    def check(
        self, spec: DetectorSpec, response: TargetResponse, ctx: DetectionContext
    ) -> DetectorHit | None: ...
