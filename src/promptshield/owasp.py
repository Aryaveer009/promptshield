"""OWASP Top 10 for LLM Applications (2025 edition) reference data."""

from __future__ import annotations

OWASP_VERSION = "2025"
OWASP_URL = "https://genai.owasp.org/llm-top-10/"

OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


def owasp_title(code: str) -> str:
    return OWASP_LLM_TOP10.get(code, "Unknown")
