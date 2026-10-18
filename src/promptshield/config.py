"""Configuration: ``promptshield.yaml`` + ``.env`` -> validated Pydantic models."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from promptshield.models import Category, Severity


class ConfigError(Exception):
    """The configuration is missing, unreadable or invalid."""


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------------- targets


class OpenAITarget(_Cfg):
    """Any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI, Azure proxy, Ollama, vLLM...)."""

    type: Literal["openai"]
    name: str = "openai-compatible"
    base_url: str = "https://api.openai.com/v1"
    model: str
    api_key_env: str | None = "OPENAI_API_KEY"
    send_system_prompt: bool = True
    tools: list[dict[str, Any]] = Field(default_factory=list)
    temperature: float = 0.0
    timeout_s: float = 60.0
    max_retries: int = Field(default=2, ge=0, le=6)


class HttpTarget(_Cfg):
    """Any JSON-over-HTTP chat endpoint; the request body is a template, the reply a JSON path."""

    type: Literal["http"]
    name: str = "http-endpoint"
    url: str
    method: Literal["POST", "PUT", "GET"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] = Field(default_factory=lambda: {"message": "{{prompt}}"})
    documents_field: str | None = None
    response_path: str = "response"
    tool_calls_path: str | None = None
    timeout_s: float = 60.0
    max_retries: int = Field(default=2, ge=0, le=6)


class CallableTarget(_Cfg):
    """A Python function ``fn(message, documents=None) -> str | dict | TargetResponse``."""

    type: Literal["callable"]
    name: str = "python-callable"
    callable: str = Field(description="'package.module:function' or 'path/to/file.py:function'")


Target = Annotated[OpenAITarget | HttpTarget | CallableTarget, Field(discriminator="type")]


# ------------------------------------------------------------------------- the rest


class AttackSelection(_Cfg):
    categories: list[Category] = Field(default_factory=list)
    ids: list[str] = Field(default_factory=list)
    exclude_ids: list[str] = Field(default_factory=list)
    min_severity: Severity | None = None
    extra_dirs: list[Path] = Field(default_factory=list)


class JudgeConfig(_Cfg):
    """Optional LLM-as-judge. Advisory only: it can flag, never change a deterministic verdict."""

    enabled: bool = False
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    api_key_env: str | None = "OPENAI_API_KEY"
    timeout_s: float = 60.0


class ScanConfig(_Cfg):
    target: Target
    canary: str | None = None
    extra_secrets: list[str] = Field(default_factory=list)
    system_prompt: str | None = None
    system_prompt_file: Path | None = None
    attacks: AttackSelection = Field(default_factory=AttackSelection)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    request_delay_s: float = Field(default=0.0, ge=0.0, le=60.0)
    output_dir: Path = Path("promptshield-reports")

    # Not part of the YAML schema: filled in by ``load_config``.
    source_path: Path | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def _prompt_sources_exclusive(self) -> ScanConfig:
        if self.system_prompt and self.system_prompt_file:
            raise ValueError("set either `system_prompt` or `system_prompt_file`, not both")
        return self

    @property
    def secrets(self) -> tuple[str, ...]:
        found = [s for s in [self.canary, *self.extra_secrets] if s]
        return tuple(dict.fromkeys(found))

    def resolved_system_prompt(self) -> str | None:
        """The reference system prompt, with ``{{canary}}`` substituted."""
        text = self.system_prompt
        if self.system_prompt_file:
            try:
                text = self.system_prompt_file.read_text(encoding="utf-8")
            except OSError as exc:
                raise ConfigError(f"cannot read system_prompt_file: {exc}") from exc
        if text and self.canary:
            text = text.replace("{{canary}}", self.canary)
        return text


# ------------------------------------------------------------------------- loading

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interpolate(value: Any, missing: set[str]) -> Any:
    """Replace ``${VAR}`` / ``${VAR:-default}`` in strings, recursively."""
    if isinstance(value, str):

        def sub(m: re.Match[str]) -> str:
            var, default = m.group(1), m.group(2)
            found = os.environ.get(var)
            if found is not None:
                return found
            if default is not None:
                return default
            missing.add(var)
            return m.group(0)

        return _ENV_REF.sub(sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v, missing) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, missing) for v in value]
    return value


def _resolve_relative(path: Path, base: Path) -> Path:
    return path if path.is_absolute() else (base / path)


def load_config(path: Path) -> ScanConfig:
    """Load ``.env`` (cwd, then the config's directory) and the YAML config at ``path``."""
    if not path.is_file():
        raise ConfigError(
            f"Config file not found: {path}. Run `promptshield init` to create a starter file."
        )
    load_dotenv(Path.cwd() / ".env", override=False)
    load_dotenv(path.parent / ".env", override=False)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping.")
    if "target" not in raw:
        raise ConfigError(
            f"{path} has no `target:` section. PromptShield never guesses a target; "
            "configure the system you own explicitly."
        )

    missing: set[str] = set()
    raw = _interpolate(raw, missing)
    if missing:
        raise ConfigError(
            "Environment variable(s) referenced in the config are not set: "
            + ", ".join(sorted(missing))
            + ". Put them in your .env file (see .env.example)."
        )

    try:
        config = ScanConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(path, exc)) from exc

    base = path.parent.resolve()
    if config.system_prompt_file:
        config.system_prompt_file = _resolve_relative(config.system_prompt_file, base)
    config.attacks.extra_dirs = [_resolve_relative(p, base) for p in config.attacks.extra_dirs]
    config.source_path = path.resolve()
    return config


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    lines = [f"Invalid configuration in {path}:"]
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        msg = err["msg"]
        if err["type"] == "extra_forbidden" and loc.split(".")[-1] in {
            "api_key",
            "apikey",
            "key",
            "token",
            "password",
        }:
            msg = "API keys never go in the config file; use `api_key_env` and set it in .env"
        lines.append(f"  - {loc}: {msg}")
    return "\n".join(lines)
