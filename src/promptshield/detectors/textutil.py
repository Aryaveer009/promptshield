"""Text helpers used by the deterministic detectors."""

from __future__ import annotations

import base64
import binascii
import codecs
import re

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")
_WORD = re.compile(r"[a-z0-9']+")

_REFUSAL_PATTERNS = re.compile(
    r"\b(i can(?:'|’)?t|i cannot|i can not|i won(?:'|’)?t|i(?:'|’)m sorry|i am sorry|sorry,|"
    r"i(?:'|’)m not able|i am not able|i(?:'|’)m unable|i am unable|unable to (?:help|assist|comply)|"
    r"can(?:'|’)?t (?:help|assist|comply|share|do)|cannot (?:help|assist|comply|share|do)|"
    r"not allowed to|against (?:my|our) (?:policy|policies|guidelines|rules)|i must decline|"
    r"i(?:'|’)m not going to|i do not have access|i don(?:'|’)t have access)\b",
    re.IGNORECASE,
)


def normalize(text: str) -> str:
    """Lowercase and drop everything except letters and digits (defeats spacing/dash tricks)."""
    return _NON_ALNUM.sub("", text.lower())


def words(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def is_refusal(text: str, window: int = 240) -> bool:
    """Heuristic: does the response open with a refusal? Only the first ``window`` chars count."""
    return bool(_REFUSAL_PATTERNS.search(text[:window]))


def snippet(text: str, needle: str, width: int = 70) -> str:
    """A short excerpt of ``text`` around the first case-insensitive match of ``needle``."""
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return text[: width * 2].replace("\n", " ")
    start = max(0, idx - width // 2)
    end = min(len(text), idx + len(needle) + width // 2)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}".replace("\n", " ")


def decoded_variants(text: str) -> list[str]:
    """Best-effort decodings (base64 / hex) of blobs found in ``text``."""
    out: list[str] = []
    for token in _B64_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                out.append(decoder(padded).decode("utf-8", errors="ignore"))
                break
            except (binascii.Error, ValueError):
                continue
    for token in _HEX_TOKEN.findall(text):
        cleaned = re.sub(r"[\s:]", "", token)
        if len(cleaned) % 2:
            continue
        try:
            out.append(bytes.fromhex(cleaned).decode("utf-8", errors="ignore"))
        except ValueError:
            continue
    return [v for v in out if v]


def find_secret(text: str, secret: str) -> str | None:
    """Return how ``secret`` appears in ``text`` (a technique label) or ``None``.

    Checks, in order: verbatim, separator/case-obfuscated, reversed, ROT13, base64, hex.
    Obfuscation checks need at least 8 alphanumerics in the secret to avoid false positives.
    """
    if not secret:
        return None
    lowered = text.lower()
    if secret.lower() in lowered:
        return "verbatim"

    norm_secret = normalize(secret)
    if len(norm_secret) < 8:
        return None
    norm_text = normalize(text)
    if norm_secret in norm_text:
        return "separator-obfuscated (spaces/dashes/case)"
    if norm_secret[::-1] in norm_text:
        return "reversed"
    if normalize(codecs.encode(secret, "rot13")) in norm_text:
        return "ROT13-encoded"
    if base64.b64encode(secret.encode()).decode().rstrip("=").lower() in lowered.replace("=", ""):
        return "base64-encoded"
    for variant in decoded_variants(text):
        if norm_secret in normalize(variant):
            return "base64/hex-encoded"
    if secret.encode().hex() in re.sub(r"[\s:]", "", lowered):
        return "hex-encoded"
    return None
