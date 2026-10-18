"""A stand-in for your own chatbot code, to show the Python-callable adapter."""

CANARY = "PSHIELD-CANARY-CHANGE-ME-5b81e0"


def answer(message: str, documents: list[str] | None = None) -> str:
    # A real app would call an LLM here; this one refuses everything, so it scores 100.
    return "I can only help with questions about your orders."
