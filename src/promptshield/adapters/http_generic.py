"""Adapter for any JSON-over-HTTP chat endpoint (templated request, JSON-path response)."""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import urlparse

import httpx

from promptshield.adapters.base import (
    TargetAdapter,
    TargetError,
    extract_path,
    fold_documents,
    parse_tool_calls,
    post_with_retry,
)
from promptshield.config import HttpTarget
from promptshield.models import TargetRequest, TargetResponse

PROMPT_PLACEHOLDER = "{{prompt}}"


def _fill(value: Any, prompt: str) -> Any:
    """Recursively substitute ``{{prompt}}`` in a JSON-like template."""
    if isinstance(value, str):
        return prompt if value == PROMPT_PLACEHOLDER else value.replace(PROMPT_PLACEHOLDER, prompt)
    if isinstance(value, dict):
        return {k: _fill(v, prompt) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, prompt) for v in value]
    return value


def _set_path(body: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node = body
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


class HttpAdapter(TargetAdapter):
    kind = "http"

    def __init__(self, config: HttpTarget, *, client: httpx.Client | None = None) -> None:
        super().__init__(config.name)
        self.config = config
        parsed = urlparse(config.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise TargetError(f"Invalid target url: {config.url!r}")
        self._host = parsed.hostname
        # Describe without query string or credentials: it ends up in reports.
        self._safe_url = f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
        self._client = client or httpx.Client(timeout=config.timeout_s)
        self._owns_client = client is None

    @property
    def host(self) -> str | None:
        return self._host

    def describe(self) -> str:
        return f"HTTP endpoint {self.config.method} {self._safe_url}"

    def build_body(self, request: TargetRequest) -> dict[str, Any]:
        if self.config.documents_field:
            body = _fill(copy.deepcopy(self.config.body), request.message)
            if request.documents:
                _set_path(body, self.config.documents_field, list(request.documents))
            return body  # type: ignore[no-any-return]
        return _fill(copy.deepcopy(self.config.body), fold_documents(request))  # type: ignore[no-any-return]

    def send(self, request: TargetRequest) -> TargetResponse:
        kwargs: dict[str, Any] = {"headers": self.config.headers}
        body = self.build_body(request)
        if self.config.method == "GET":
            kwargs["params"] = {k: str(v) for k, v in body.items()}
        else:
            kwargs["json"] = body
        response = post_with_retry(
            self._client,
            self.config.method,
            self.config.url,
            retries=self.config.max_retries,
            **kwargs,
        )
        try:
            data = response.json()
        except ValueError as exc:
            raise TargetError("Target did not return JSON; check `response_path`.") from exc
        try:
            raw_text = extract_path(data, self.config.response_path)
        except KeyError as exc:
            raise TargetError(str(exc)) from exc
        text = raw_text if isinstance(raw_text, str) else str(raw_text)
        tool_calls = []
        if self.config.tool_calls_path:
            try:
                tool_calls = parse_tool_calls(extract_path(data, self.config.tool_calls_path))
            except KeyError:
                tool_calls = []  # the field is simply absent when no tool was called
        return TargetResponse(text=text, tool_calls=tool_calls)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
