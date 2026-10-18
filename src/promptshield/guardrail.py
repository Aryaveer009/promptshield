"""Safety guardrail: PromptShield refuses to attack anything the operator hasn't claimed.

Rules enforced *before* any request is sent or any user code is imported:

1. The operator must pass ``--i-own-this-target``.
2. The target must be explicitly configured in a config file (no implicit/default target).
3. Well-known consumer chat products (ChatGPT, Claude.ai, Gemini...) are refused outright:
   nobody "owns" those, and attacking them violates their terms.
"""

from __future__ import annotations

from pathlib import Path

from promptshield.adapters.base import TargetAdapter

OWNERSHIP_FLAG = "--i-own-this-target"

OPERATOR_ATTESTATION = (
    "Operator attested via --i-own-this-target that they own this target or hold explicit "
    "written permission to security-test it."
)
DEMO_ATTESTATION = "Bundled in-process demo target: no network access, no third-party system."

# Consumer chat products and public web UIs. API endpoints you own/pay for are fine; these are not.
BLOCKED_HOSTS = (
    "chat.openai.com",
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "bard.google.com",
    "copilot.microsoft.com",
    "bing.com",
    "perplexity.ai",
    "poe.com",
    "character.ai",
    "grok.com",
    "chat.deepseek.com",
    "meta.ai",
)


class GuardrailError(Exception):
    """Raised when a scan is not authorised. The message tells the user how to proceed."""


def check_acknowledged(acknowledged: bool) -> None:
    if not acknowledged:
        raise GuardrailError(
            f"Refusing to run: pass {OWNERSHIP_FLAG} to confirm you own this target or have "
            "explicit written permission to test it.\n"
            "PromptShield sends real attack prompts; only run it against systems that are yours."
        )


def check_configured(config_path: Path | None) -> None:
    if config_path is None or not config_path.is_file():
        raise GuardrailError(
            "Refusing to run: no target is configured. Create a config with `promptshield init` "
            "and set `target:` explicitly. PromptShield never guesses what to attack."
        )


def is_blocked_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return any(host == b or host.endswith("." + b) for b in BLOCKED_HOSTS)


def check_target_allowed(adapter: TargetAdapter) -> None:
    if is_blocked_host(adapter.host):
        raise GuardrailError(
            f"Refusing to run: {adapter.host} is a public consumer service, not a target you "
            "own. Test your own application's API instead."
        )


def authorize_pre_flight(*, acknowledged: bool, config_path: Path | None) -> None:
    """Checks that must pass before the config target is even instantiated."""
    check_acknowledged(acknowledged)
    check_configured(config_path)
