"""Real-socket integration test: scan the demo bot through the generic HTTP adapter."""

from __future__ import annotations

import importlib.util
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from promptshield.adapters import CallableAdapter, HttpAdapter
from promptshield.attacks import load_attacks
from promptshield.config import HttpTarget
from promptshield.demo import demo_config
from promptshield.demo.hardened import chat as hardened_chat
from promptshield.detectors import DetectionContext
from promptshield.runner import build_result, run_scan

SERVER_SCRIPT = Path(__file__).resolve().parent.parent / "examples" / "demo_http_server.py"


@pytest.fixture
def server_url() -> Iterator[str]:
    spec = importlib.util.spec_from_file_location("demo_http_server", SERVER_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    httpd = module.serve(hardened_chat, port=0)  # port 0: the OS picks a free port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/chat"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_scanning_a_live_http_endpoint_matches_in_process_results(server_url: str) -> None:
    target = HttpTarget.model_validate(
        {
            "type": "http",
            "url": server_url,
            "documents_field": "documents",
            "response_path": "data.reply",
            "tool_calls_path": "data.tool_calls",
        }
    )
    cfg = demo_config("hardened")
    ctx = DetectionContext(secrets=cfg.secrets, system_prompt=cfg.resolved_system_prompt())
    attacks = load_attacks()
    with HttpAdapter(target) as adapter:
        findings = run_scan(adapter, attacks, ctx)
        result = build_result(
            findings=findings,
            adapter=adapter,
            target_type="http",
            attestation="test",
            started_at=datetime.now(UTC),
        )
    assert result.errors == 0 and result.skipped == 0
    in_process = run_scan(
        CallableAdapter(hardened_chat),
        attacks,
        ctx,
    )
    assert [f.verdict for f in findings] == [f.verdict for f in in_process]
