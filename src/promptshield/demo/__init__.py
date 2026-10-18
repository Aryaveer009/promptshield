"""Bundled demo: an intentionally vulnerable chatbot and a hardened version."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from promptshield.config import CallableTarget, ScanConfig
from promptshield.demo.data import CANARY, DEMO_SECRETS

DEMO_TARGETS: dict[str, str] = {
    "vulnerable": "promptshield.demo.vulnerable:chat",
    "hardened": "promptshield.demo.hardened:chat",
}


def system_prompt_path() -> Path:
    return Path(str(resources.files("promptshield.demo").joinpath("system_prompt.txt")))


def demo_config(which: str) -> ScanConfig:
    """A ready-made ScanConfig for one of the bundled demo targets."""
    return ScanConfig(
        target=CallableTarget(
            type="callable", name=f"acmebot-{which}", callable=DEMO_TARGETS[which]
        ),
        canary=CANARY,
        extra_secrets=[s for s in DEMO_SECRETS if s != CANARY],
        system_prompt_file=system_prompt_path(),
    )
