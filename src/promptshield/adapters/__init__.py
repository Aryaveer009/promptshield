"""Target adapters: OpenAI-compatible, generic HTTP, Python callable (+ an offline mock)."""

from __future__ import annotations

from pathlib import Path

from promptshield.adapters.base import TargetAdapter, TargetError
from promptshield.adapters.http_generic import HttpAdapter
from promptshield.adapters.mock import MockTarget
from promptshield.adapters.openai_compat import OpenAICompatAdapter
from promptshield.adapters.python_callable import CallableAdapter, load_callable
from promptshield.config import CallableTarget, HttpTarget, OpenAITarget, ScanConfig


def create_adapter(config: ScanConfig) -> TargetAdapter:
    """Build the adapter for ``config.target``. Raises ``TargetError`` on bad target settings."""
    target = config.target
    if isinstance(target, OpenAITarget):
        return OpenAICompatAdapter(target, system_prompt=config.resolved_system_prompt())
    if isinstance(target, HttpTarget):
        return HttpAdapter(target)
    if isinstance(target, CallableTarget):
        base = config.source_path.parent if config.source_path else Path.cwd()
        return CallableAdapter(load_callable(target.callable, base), name=target.name)
    raise TargetError(f"Unsupported target type: {target!r}")  # pragma: no cover


__all__ = [
    "CallableAdapter",
    "HttpAdapter",
    "MockTarget",
    "OpenAICompatAdapter",
    "TargetAdapter",
    "TargetError",
    "create_adapter",
    "load_callable",
]
