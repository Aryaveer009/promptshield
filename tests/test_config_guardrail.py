from __future__ import annotations

from pathlib import Path

import pytest

from promptshield.adapters import MockTarget
from promptshield.config import ConfigError, load_config
from promptshield.guardrail import (
    GuardrailError,
    authorize_pre_flight,
    check_target_allowed,
    is_blocked_host,
)

VALID = """\
target:
  type: openai
  model: m
  base_url: https://llm.test/v1
canary: CANARY-abc12345
system_prompt: "Hello {{canary}}"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "promptshield.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_valid_config_and_canary_substitution(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, VALID))
    assert cfg.target.type == "openai"
    assert cfg.secrets == ("CANARY-abc12345",)
    assert cfg.resolved_system_prompt() == "Hello CANARY-abc12345"


def test_missing_config_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_config_without_target_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="target"):
        load_config(write(tmp_path, "canary: abc\n"))


def test_api_keys_are_rejected_in_config(tmp_path: Path) -> None:
    bad = VALID.replace("model: m", "model: m\n  api_key: sk-should-not-be-here")
    with pytest.raises(ConfigError, match="API keys never go in the config"):
        load_config(write(tmp_path, bad))


def test_env_interpolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_TOKEN", "tok-123")
    text = """\
target:
  type: http
  url: http://localhost:9/chat
  headers: {Authorization: "Bearer ${APP_TOKEN}", X-Other: "${NOPE:-fallback}"}
"""
    cfg = load_config(write(tmp_path, text))
    assert cfg.target.headers == {"Authorization": "Bearer tok-123", "X-Other": "fallback"}  # type: ignore[union-attr]


def test_missing_env_var_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFINITELY_UNSET_VAR", raising=False)
    text = "target:\n  type: http\n  url: http://localhost:9/${DEFINITELY_UNSET_VAR}\n"
    with pytest.raises(ConfigError, match="DEFINITELY_UNSET_VAR"):
        load_config(write(tmp_path, text))


def test_relative_paths_resolve_against_config_dir(tmp_path: Path) -> None:
    (tmp_path / "prompt.txt").write_text("from file {{canary}}", encoding="utf-8")
    text = (
        "target: {type: openai, model: m, base_url: 'https://llm.test/v1'}\n"
        "canary: CANARY-abc12345\nsystem_prompt_file: prompt.txt\n"
    )
    cfg = load_config(write(tmp_path, text))
    assert cfg.resolved_system_prompt() == "from file CANARY-abc12345"


def test_system_prompt_and_file_are_mutually_exclusive(tmp_path: Path) -> None:
    text = VALID + "system_prompt_file: x.txt\n"
    with pytest.raises(ConfigError, match="either"):
        load_config(write(tmp_path, text))


# ------------------------------------------------------------------ guardrail


def test_refuses_without_ownership_flag(tmp_path: Path) -> None:
    path = write(tmp_path, VALID)
    with pytest.raises(GuardrailError, match="--i-own-this-target"):
        authorize_pre_flight(acknowledged=False, config_path=path)


def test_refuses_without_configured_target(tmp_path: Path) -> None:
    with pytest.raises(GuardrailError, match="no target is configured"):
        authorize_pre_flight(acknowledged=True, config_path=tmp_path / "missing.yaml")
    with pytest.raises(GuardrailError, match="no target is configured"):
        authorize_pre_flight(acknowledged=True, config_path=None)


def test_allows_when_flag_and_config_present(tmp_path: Path) -> None:
    authorize_pre_flight(acknowledged=True, config_path=write(tmp_path, VALID))


@pytest.mark.parametrize(
    ("host", "blocked"),
    [
        ("chatgpt.com", True),
        ("chat.openai.com", True),
        ("www.claude.ai", True),
        ("gemini.google.com", True),
        ("api.openai.com", False),
        ("localhost", False),
        ("myapp.example.com", False),
        ("notchatgpt.com", False),
        (None, False),
    ],
)
def test_blocked_consumer_hosts(host: str | None, blocked: bool) -> None:
    assert is_blocked_host(host) is blocked


def test_check_target_allowed_for_in_process_target() -> None:
    check_target_allowed(MockTarget("x"))  # no host -> allowed
