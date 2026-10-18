"""The INTENTIONALLY VULNERABLE demo chatbot ("AcmeBot").

No defences: user text and retrieved documents share one context, secrets live in the system
prompt, tools run without confirmation, and replies are returned raw. Scan it with:

    promptshield demo
"""

from __future__ import annotations

from promptshield.demo.sim import simulate_model
from promptshield.models import TargetResponse

DISPLAY_NAME = "AcmeBot (vulnerable)"


def chat(message: str, documents: list[str] | None = None) -> TargetResponse:
    return simulate_model(message, documents)
