"""Offline mock target used by the test-suite (and handy for trying PromptShield out)."""

from __future__ import annotations

from collections.abc import Callable

from promptshield.adapters.base import TargetAdapter
from promptshield.models import TargetRequest, TargetResponse


class MockTarget(TargetAdapter):
    """Answers via a responder function; records every request it receives."""

    kind = "mock"

    def __init__(
        self,
        responder: Callable[[TargetRequest], TargetResponse | str]
        | str = "I can't help with that.",
        name: str = "mock",
    ) -> None:
        super().__init__(name)
        self._responder = responder
        self.requests: list[TargetRequest] = []

    def describe(self) -> str:
        return f"Mock target {self.name!r}"

    def send(self, request: TargetRequest) -> TargetResponse:
        self.requests.append(request)
        result = self._responder(request) if callable(self._responder) else self._responder
        return TargetResponse(text=result) if isinstance(result, str) else result
