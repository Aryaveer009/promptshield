from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from promptshield.adapters import (
    CallableAdapter,
    HttpAdapter,
    MockTarget,
    OpenAICompatAdapter,
    TargetError,
    load_callable,
)
from promptshield.adapters.base import extract_path, parse_tool_calls, post_with_retry
from promptshield.config import HttpTarget, OpenAITarget
from promptshield.models import TargetRequest, TargetResponse, ToolCall


def client_for(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


# ------------------------------------------------------------------ helpers


def test_extract_path() -> None:
    data = {"a": {"b": [{"c": "x"}, {"c": "y"}]}}
    assert extract_path(data, "a.b[1].c") == "y"
    with pytest.raises(KeyError):
        extract_path(data, "a.z")
    with pytest.raises(KeyError):
        extract_path(data, "a.b[5].c")


def test_parse_tool_calls_openai_and_simple_shapes() -> None:
    raw = [
        {"function": {"name": "send_email", "arguments": '{"to": "a@b.c"}'}},
        {"name": "lookup_order", "arguments": {"order_id": "1"}},
        {"function": {"name": "broken", "arguments": "not json"}},
        {"nothing": True},
    ]
    calls = parse_tool_calls(raw)
    assert [c.name for c in calls] == ["send_email", "lookup_order", "broken"]
    assert calls[0].arguments == {"to": "a@b.c"}
    assert calls[2].arguments == {"_raw": "not json"}
    assert parse_tool_calls(None) == []


def test_retry_then_success() -> None:
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(429 if attempts["n"] < 3 else 200, json={"ok": True})

    sleeps: list[float] = []
    with client_for(handler) as client:
        resp = post_with_retry(client, "POST", "http://x.test", retries=3, sleep=sleeps.append)
    assert resp.status_code == 200 and attempts["n"] == 3 and len(sleeps) == 2


def test_no_retry_on_client_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="nope")

    with client_for(handler) as client, pytest.raises(TargetError, match="401"):
        post_with_retry(client, "POST", "http://x.test", retries=3, sleep=lambda s: None)


# ------------------------------------------------------------------ callable


def test_callable_str_dict_and_response_results() -> None:
    assert CallableAdapter(lambda m: "hi").send(TargetRequest(message="x")).text == "hi"
    out = CallableAdapter(
        lambda m: {"answer": "yo", "tool_calls": [{"name": "t", "arguments": {"a": 1}}]}
    ).send(TargetRequest(message="x"))
    assert out.text == "yo" and out.tool_calls == [ToolCall(name="t", arguments={"a": 1})]
    resp = TargetResponse(text="direct")
    assert CallableAdapter(lambda m: resp).send(TargetRequest(message="x")).text == "direct"


def test_callable_receives_documents_kwarg_when_supported() -> None:
    seen: dict[str, object] = {}

    def fn(message: str, documents: list[str] | None = None) -> str:
        seen.update(message=message, documents=documents)
        return "ok"

    CallableAdapter(fn).send(TargetRequest(message="q", documents=["doc"]))
    assert seen == {"message": "q", "documents": ["doc"]}


def test_callable_without_documents_param_gets_folded_prompt() -> None:
    seen: list[str] = []
    CallableAdapter(lambda m: seen.append(m) or "ok").send(
        TargetRequest(message="q", documents=["POISON"])
    )
    assert "POISON" in seen[0] and "q" in seen[0]


def test_callable_exception_becomes_target_error() -> None:
    def boom(message: str) -> str:
        raise RuntimeError("kaput")

    with pytest.raises(TargetError, match="kaput"):
        CallableAdapter(boom).send(TargetRequest(message="x"))


def test_load_callable_from_module_and_file(tmp_path: Path) -> None:
    assert callable(load_callable("promptshield.demo.vulnerable:chat"))
    script = tmp_path / "my_app.py"
    script.write_text("def answer(message):\n    return 'from file: ' + message\n")
    func = load_callable("my_app.py:answer", base_dir=tmp_path)
    assert func("x") == "from file: x"


@pytest.mark.parametrize(
    "spec", ["nocolon", "missing.module:fn", "promptshield.demo.vulnerable:nope"]
)
def test_load_callable_errors(spec: str) -> None:
    with pytest.raises(TargetError):
        load_callable(spec)


# ------------------------------------------------------------------ http


def make_http(**overrides: object) -> HttpTarget:
    data: dict[str, object] = {
        "type": "http",
        "url": "http://localhost:8000/chat?token=abc",
        "response_path": "data.reply",
    }
    data.update(overrides)
    return HttpTarget.model_validate(data)


def test_http_adapter_template_and_json_path() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": {"reply": "hello", "tool_calls": [{"name": "t"}]}})

    cfg = make_http(
        headers={"Authorization": "Bearer abc"},
        body={"session": 1, "input": {"text": "{{prompt}}"}},
        tool_calls_path="data.tool_calls",
    )
    with HttpAdapter(cfg, client=client_for(handler)) as adapter:
        out = adapter.send(TargetRequest(message="attack"))
    assert captured["body"] == {"session": 1, "input": {"text": "attack"}}
    assert captured["auth"] == "Bearer abc"
    assert out.text == "hello" and out.tool_calls[0].name == "t"


def test_http_adapter_documents_field_vs_folding() -> None:
    bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"data": {"reply": "ok"}})

    req = TargetRequest(message="question", documents=["POISONED"])
    with HttpAdapter(make_http(documents_field="ctx.docs"), client=client_for(handler)) as a:
        a.send(req)
    assert bodies[0]["ctx"] == {"docs": ["POISONED"]}
    assert bodies[0]["message"] == "question"

    with HttpAdapter(make_http(), client=client_for(handler)) as a:
        a.send(req)
    assert "POISONED" in str(bodies[1]["message"]) and "question" in str(bodies[1]["message"])


def test_http_adapter_errors() -> None:
    with (
        HttpAdapter(
            make_http(max_retries=0), client=client_for(lambda r: httpx.Response(500, text="boom"))
        ) as a,
        pytest.raises(TargetError, match="500"),
    ):
        a.send(TargetRequest(message="x"))

    with (
        HttpAdapter(
            make_http(), client=client_for(lambda r: httpx.Response(200, json={"wrong": 1}))
        ) as a,
        pytest.raises(TargetError, match="data"),
    ):
        a.send(TargetRequest(message="x"))

    with (
        HttpAdapter(
            make_http(), client=client_for(lambda r: httpx.Response(200, text="<html>"))
        ) as a,
        pytest.raises(TargetError, match="JSON"),
    ):
        a.send(TargetRequest(message="x"))

    with pytest.raises(TargetError, match="Invalid target url"):
        HttpAdapter(make_http(url="ftp://nope"))


def test_http_adapter_description_hides_query_string() -> None:
    adapter = HttpAdapter(make_http(), client=client_for(lambda r: httpx.Response(200)))
    assert "token=abc" not in adapter.describe()
    assert adapter.host == "localhost"


# ------------------------------------------------------------------ openai-compatible


def openai_cfg(**overrides: object) -> OpenAITarget:
    data: dict[str, object] = {
        "type": "openai",
        "model": "test-model",
        "base_url": "https://llm.test/v1",
    }
    data.update(overrides)
    return OpenAITarget.model_validate(data)


def test_openai_adapter_payload_and_parsing() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers["authorization"]
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "send_email",
                                        "arguments": '{"to": "x@evil.example"}',
                                    }
                                }
                            ],
                        }
                    }
                ]
            },
        )

    tools = [{"type": "function", "function": {"name": "send_email", "parameters": {}}}]
    adapter = OpenAICompatAdapter(
        openai_cfg(tools=tools),
        system_prompt="You are a bot. {x}",
        client=client_for(handler),
        environ={"OPENAI_API_KEY": "test-key-not-real"},
    )
    out = adapter.send(TargetRequest(message="hi", documents=["DOC"]))

    assert captured["url"] == "https://llm.test/v1/chat/completions"
    assert captured["auth"] == "Bearer test-key-not-real"
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["model"] == "test-model" and body["tools"] == tools
    assert body["messages"][0] == {"role": "system", "content": "You are a bot. {x}"}
    assert "DOC" in body["messages"][1]["content"]
    assert out.text == "" and out.tool_calls[0].arguments == {"to": "x@evil.example"}


def test_openai_adapter_can_skip_system_prompt() -> None:
    bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    adapter = OpenAICompatAdapter(
        openai_cfg(send_system_prompt=False),
        system_prompt="SECRET PROMPT",
        client=client_for(handler),
        environ={"OPENAI_API_KEY": "k"},
    )
    adapter.send(TargetRequest(message="hi"))
    assert [m["role"] for m in bodies[0]["messages"]] == ["user"]  # type: ignore[attr-defined]


def test_openai_adapter_requires_key_for_remote_hosts_but_not_localhost() -> None:
    with pytest.raises(TargetError, match="OPENAI_API_KEY"):
        OpenAICompatAdapter(openai_cfg(), environ={})
    local = OpenAICompatAdapter(
        openai_cfg(base_url="http://localhost:11434/v1"),
        client=client_for(
            lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})
        ),
        environ={},
    )
    assert local.send(TargetRequest(message="hi")).text == "x"


def test_openai_adapter_bad_shape() -> None:
    adapter = OpenAICompatAdapter(
        openai_cfg(max_retries=0),
        client=client_for(lambda r: httpx.Response(200, json={"unexpected": True})),
        environ={"OPENAI_API_KEY": "k"},
    )
    with pytest.raises(TargetError, match="Unexpected response"):
        adapter.send(TargetRequest(message="hi"))


# ------------------------------------------------------------------ mock


def test_mock_target_records_requests() -> None:
    mock = MockTarget("fixed")
    assert mock.send(TargetRequest(message="a")).text == "fixed"
    assert mock.requests[0].message == "a"
