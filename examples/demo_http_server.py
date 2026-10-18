"""Serve a bundled demo bot over HTTP so you can try PromptShield's generic HTTP adapter.

    python examples/demo_http_server.py --port 8000            # vulnerable bot
    python examples/demo_http_server.py --port 8000 --hardened

Then, in another terminal:

    promptshield scan -c examples/http-endpoint.yaml --i-own-this-target

Binds to 127.0.0.1 only. Request:  POST /chat {"message": "...", "documents": ["..."]}
Response: {"data": {"reply": "...", "tool_calls": [{"name": "...", "arguments": {...}}]}}

Built by Aryaveer Mankotia (https://github.com/Aryaveer009)
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from promptshield.demo import hardened, vulnerable


def make_handler(chat: Any) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/chat":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self.send_error(400, "invalid JSON")
                return
            reply = chat(str(payload.get("message", "")), payload.get("documents") or [])
            body = json.dumps(
                {
                    "data": {
                        "reply": reply.text,
                        "tool_calls": [c.model_dump() for c in reply.tool_calls],
                    }
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # silence request logging
            return

    return Handler


def serve(chat: Any, port: int = 8000) -> HTTPServer:
    return HTTPServer(("127.0.0.1", port), make_handler(chat))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--hardened", action="store_true", help="serve the hardened bot")
    args = parser.parse_args()
    bot = hardened.chat if args.hardened else vulnerable.chat
    server = serve(bot, args.port)
    print(
        f"Serving {'hardened' if args.hardened else 'vulnerable'} demo bot on http://127.0.0.1:{args.port}/chat"
    )
    server.serve_forever()
