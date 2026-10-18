"""Adapter for OpenAI-compatible ``/chat/completions`` endpoints."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import httpx

from promptshield.adapters.base import (
    TargetAdapter,
    TargetError,
    fold_documents,
    parse_tool_calls,
    post_with_retry,
)
from promptshield.config import OpenAITarget
from promptshield.models import TargetRequest, TargetResponse

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class OpenAICompatAdapter(TargetAdapter):
    kind = "openai"

    def __init__(
        self,
        config: OpenAITarget,
        *,
        system_prompt: str | None = None,
        client: httpx.Client | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(config.name)
        self.config = config
        self.system_prompt = system_prompt if config.send_system_prompt else None
        self._url = config.base_url.rstrip("/") + "/chat/completions"
        self._host = urlparse(config.base_url).hostname or ""

        env = os.environ if environ is None else environ
        headers = {"Content-Type": "application/json"}
        if config.api_key_env:
            key = env.get(config.api_key_env)
            if key:
                headers["Authorization"] = f"Bearer {key}"
            elif self._host not in _LOCAL_HOSTS:
                raise TargetError(
                    f"Environment variable {config.api_key_env} is not set. "
                    "Add it to your .env file (see .env.example); never put keys in the config."
                )
        self._client = client or httpx.Client(timeout=config.timeout_s)
        self._owns_client = client is None
        self._headers = headers

    @property
    def host(self) -> str | None:
        return self._host or None

    def describe(self) -> str:
        return f"OpenAI-compatible endpoint {self.config.base_url} (model {self.config.model})"

    def send(self, request: TargetRequest) -> TargetResponse:
        messages: list[dict[str, Any]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": fold_documents(request)})
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
        }
        if self.config.tools:
            payload["tools"] = self.config.tools

        response = post_with_retry(
            self._client,
            "POST",
            self._url,
            retries=self.config.max_retries,
            headers=self._headers,
            json=payload,
        )
        try:
            message = response.json()["choices"][0]["message"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise TargetError(f"Unexpected response shape from {self._url}: {exc}") from exc
        return TargetResponse(
            text=message.get("content") or "",
            tool_calls=parse_tool_calls(message.get("tool_calls")),
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
