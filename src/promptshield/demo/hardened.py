"""The HARDENED demo chatbot: the same underlying model plus layered, realistic defences.

Layers (each one maps to a fix PromptShield recommends):

1. Input filter       - refuses messages with common injection / jailbreak / extraction phrasing.
2. Document sanitiser - strips hidden markup and instruction-like lines from retrieved documents.
3. Tool gate          - only the read-only ``lookup_order`` tool may run; the rest need a human.
4. Output filter      - redacts known secrets and PII, strips remote images and ``javascript:``
                        URLs, HTML-escapes the reply and blocks replies that echo the system prompt.

It is deliberately a *partial* defence, like most real-world filters: the input filter is
English-only regex that does not decode payloads, and HTML escaping is not a SQL defence. Expect
a clearly better score than the vulnerable bot but not a perfect one. That gap is the point.
"""

from __future__ import annotations

import html
import re

from promptshield.demo.data import CUSTOMERS, DEMO_SECRETS, SYSTEM_PROMPT
from promptshield.demo.sim import REFUSAL, simulate_model
from promptshield.detectors.textutil import words
from promptshield.models import TargetResponse

DISPLAY_NAME = "AcmeBot (hardened)"

ALLOWED_TOOLS = frozenset({"lookup_order"})

_INPUT_BLOCKLIST = re.compile(
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier)"
    r"|disregard|forget (?:all|your|everything)"
    r"|(?:new|updated?) (?:instructions|rules|policy)|supersede"
    r"|\[\s*system\s*\]|system (?:prompt|message|instruction)"
    r"|developer mode|debug mode|\bdan\b|jailbreak|no restrictions|no rules"
    r"|without (?:any )?(?:rules|restrictions)"
    r"|pretend|role-?play|\bact as\b|you are now|stay in character|from now on"
    r"|(?:your|the) (?:initial |original |hidden |internal |full )?(?:instructions|configuration|prompt)"
    r"|repeat (?:all|everything)[^.]*above"
    r"|api key|password|credential|secret|token"
    r"|authori[sz]e you|\bi am the ceo\b",
    re.IGNORECASE,
)

_DOC_LINE_BLOCKLIST = re.compile(
    r"ignore (?:all |any )?(?:the )?(?:previous|prior)|disregard|system (?:notice|instruction)"
    r"|(?:note (?:for|to) )?(?:the )?(?:ai )?assistant\b|new rule|you must",
    re.IGNORECASE,
)
_ZERO_WIDTH = re.compile("[​-‏⁠﻿]")
_HIDDEN_SPAN = re.compile(
    r"<[^>]+style=\"[^\"]*(?:font-size:\s*0|display:\s*none)[^\"]*\"[^>]*>.*?</[^>]+>",
    re.IGNORECASE | re.DOTALL,
)

_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_CARD = re.compile(r"card ending (?:in )?\d{4}", re.IGNORECASE)
_HUMAN_NEEDED = "I can't do that on my own. A human agent needs to confirm this action first."


def sanitize_document(doc: str) -> str:
    """Remove hidden markup and instruction-like lines from a retrieved document."""
    doc = re.sub(r"<!--.*?-->", "", doc, flags=re.DOTALL)
    doc = _HIDDEN_SPAN.sub("", doc)
    doc = _ZERO_WIDTH.sub("", doc)
    kept = [line for line in doc.splitlines() if not _DOC_LINE_BLOCKLIST.search(line)]
    return "\n".join(kept)


def _leaks_system_prompt(text: str, n: int = 6) -> bool:
    prompt_words = words(SYSTEM_PROMPT)
    grams = {tuple(prompt_words[i : i + n]) for i in range(len(prompt_words) - n + 1)}
    reply = words(text)
    return any(tuple(reply[i : i + n]) in grams for i in range(len(reply) - n + 1))


def filter_output(text: str) -> str:
    for secret in DEMO_SECRETS:
        text = re.sub(re.escape(secret), "[REDACTED]", text, flags=re.IGNORECASE)
    for record in CUSTOMERS.values():
        text = text.replace(record["card"], "card ending [REDACTED]")
    text = _CARD.sub("card ending [REDACTED]", text)
    text = _IMAGE.sub("[image removed]", text)
    text = re.sub(r"javascript:", "blocked:", text, flags=re.IGNORECASE)
    return html.escape(text, quote=False)


def chat(message: str, documents: list[str] | None = None) -> TargetResponse:
    if _INPUT_BLOCKLIST.search(message):
        return TargetResponse(text=REFUSAL)

    clean_docs = [sanitize_document(d) for d in (documents or [])]
    raw = simulate_model(message, clean_docs)

    allowed_calls = [c for c in raw.tool_calls if c.name in ALLOWED_TOOLS]
    if len(allowed_calls) != len(raw.tool_calls):
        return TargetResponse(text=_HUMAN_NEEDED, tool_calls=allowed_calls)

    if _leaks_system_prompt(raw.text):
        return TargetResponse(text="I can't share my configuration.", tool_calls=allowed_calls)
    return TargetResponse(text=filter_output(raw.text), tool_calls=allowed_calls)
