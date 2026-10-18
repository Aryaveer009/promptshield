"""Target adapter interface: how PromptShield talks to the app under test."""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, ClassVar

import httpx

from promptshield.models import TargetRequest, TargetResponse, ToolCall


class TargetError(RuntimeError):
    """The target could not be reached, returned an error, or answered in an unusable shape."""


class TargetAdapter(ABC):
    kind: ClassVar[str]

    def __init__(self, name: str) -> None:
        self.name = name

    @property
    def host(self) -> str | None:
        """Network host being attacked (``None`` for in-process targets)."""
        return None

    @abstractmethod
    def describe(self) -> str:
        """Human-readable target description for banners and reports (never contains secrets)."""

    @abstractmethod
    def send(self, request: TargetRequest) -> TargetResponse: ...

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release resources (HTTP clients)."""

    def __enter__(self) -> TargetAdapter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def render_documents(documents: list[str]) -> str:
    """Format retrieved documents the way a typical RAG prompt would present them."""
    blocks = [f"[Document {i}]\n{doc.strip()}" for i, doc in enumerate(documents, start=1)]
    return "Retrieved context:\n" + "\n\n".join(blocks)


def fold_documents(request: TargetRequest) -> str:
    """Single-string form of a request, for targets without a separate documents channel."""
    if not request.documents:
        return request.message
    return f"{render_documents(request.documents)}\n\nUser question: {request.message}"


# ------------------------------------------------------------------ JSON path helper

_TOKEN = re.compile(r"[^.\[\]]+|\[\d+\]")


def extract_path(data: Any, path: str) -> Any:
    """Resolve a dotted JSON path like ``choices[0].message.content``. Raises ``KeyError``."""
    current = data
    for token in _TOKEN.findall(path):
        try:
            current = current[int(token[1:-1])] if token.startswith("[") else current[token]
        except (KeyError, IndexError, TypeError) as exc:
            raise KeyError(f"path {path!r} not found in response (failed at {token!r})") from exc
    return current


def parse_tool_calls(raw: Any) -> list[ToolCall]:
    """Normalise tool calls from OpenAI-style or simple ``{name, arguments}`` shapes."""
    calls: list[ToolCall] = []
    if not isinstance(raw, list):
        return calls
    for item in raw:
        if not isinstance(item, dict):
            continue
        nested = item.get("function")
        fn: dict[str, Any] = nested if isinstance(nested, dict) else item
        name = fn.get("name")
        if not name:
            continue
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"_raw": args}
        if not isinstance(args, dict):
            args = {"_raw": args}
        calls.append(ToolCall(name=str(name), arguments=args))
    return calls


# ------------------------------------------------------------------ HTTP with retries


def post_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    retries: int,
    sleep: Callable[[float], None] = time.sleep,
    **kwargs: Any,
) -> httpx.Response:
    """Send a request, retrying on network errors / 429 / 5xx with exponential backoff."""
    last_error: str = ""
    for attempt in range(retries + 1):
        try:
            response = client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        else:
            if response.status_code < 400:
                return response
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
            if response.status_code not in {408, 409, 425, 429, 500, 502, 503, 504}:
                break
        if attempt < retries:
            sleep(min(2**attempt, 8))
    raise TargetError(last_error or "request failed")
