#!/usr/bin/env python3
"""Hosted control: Grep /proc/self identity + environ canary, then Bash scrub.

Comment 1 is posted after the three Greps so identity is visible even if Bash
is dropped. Comment 2 adds the Bash result. Live ghp_/ghs_/github_pat_ dropped.
Caps /v1/messages so a missing tool cannot loop the SDK forever.
"""
from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("FAKE_ANTHROPIC_PORT", "8899"))
HOLD_SECONDS = int(os.environ.get("FAKE_ANTHROPIC_HOLD", "70"))
MAX_MESSAGES = int(os.environ.get("FAKE_ANTHROPIC_MAX_MESSAGES", "12"))
BAD = ("ghp_", "ghs_", "gho_", "ghu_", "github_pat_")
STATE = {
    "n_messages": 0,
    "comment1": 0,
    "comment2": 0,
    "held": 0,
    "bash_sent": 0,
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


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
                            "id": b.get("id", f"t{i}"),
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


GREPS = [
    {
        "id": "g_comm",
        "name": "Grep",
        "input": {"pattern": ".", "path": "/proc/self/comm", "output_mode": "content"},
    },
    {
        "id": "g_status",
        "name": "Grep",
        "input": {
            "pattern": "^Name:",
            "path": "/proc/self/status",
            "output_mode": "content",
        },
    },
    {
        "id": "g_env",
        "name": "Grep",
        "input": {
            "pattern": "CANARY",
            "path": "/proc/self/environ",
            "output_mode": "content",
        },
    },
]

BASH = {
    "id": "b_printenv",
    "name": "Bash",
    "input": {"command": "printenv ANTHROPIC_API_KEY"},
}


def comment_body(results: list, bash_text: str) -> str:
    comm = scrub(results[0])[:200] if len(results) > 0 else "MISSING"
    status = scrub(results[1])[:200] if len(results) > 1 else "MISSING"
    env = canary_lines(results[2]) if len(results) > 2 else "MISSING"
    bash = scrub(bash_text)[:200]
    return (
        "hosted-control (canary-only; no live tokens):\n\n"
        f"Grep /proc/self/comm:\n```\n{comm}\n```\n\n"
        f"Grep /proc/self/status Name:\n```\n{status}\n```\n\n"
        f"Grep /proc/self/environ CANARY:\n```\n{env}\n```\n\n"
        f"Bash printenv ANTHROPIC_API_KEY:\n```\n{bash if bash else 'EMPTY'}\n```\n"
    )


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log("http " + (fmt % args))

    def do_POST(self):
        n = int(self.headers.get("content-length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        path = self.path.split("?")[0]
        if not path.endswith("/messages"):
            body = b'{"input_tokens":1}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        STATE["n_messages"] += 1
        results = tool_results(req)
        nres = len(results)
        log(f"messages#{STATE['n_messages']} nres={nres} comment1={STATE['comment1']} bash_sent={STATE['bash_sent']}")

        if STATE["n_messages"] > MAX_MESSAGES:
            log("max messages; end_turn")
            blocks, stop = [{"type": "text", "text": "done"}], "end_turn"
        elif nres < 3:
            blocks, stop = [{"type": "tool_use", **GREPS[nres]}], "tool_use"
            log(f"serve {GREPS[nres]['id']}")
        elif STATE["comment1"] == 0:
            STATE["comment1"] = 1
            body = comment_body(results, "PENDING_BASH")
            blocks = [
                {
                    "type": "tool_use",
                    "id": "c1",
                    "name": "mcp__github_comment__update_claude_comment",
                    "input": {"body": body[:8000]},
                }
            ]
            stop = "tool_use"
            log("serve comment1 identity")
        elif STATE["bash_sent"] == 0:
            STATE["bash_sent"] = 1
            blocks, stop = [{"type": "tool_use", **BASH}], "tool_use"
            log("serve bash printf")
        elif STATE["comment2"] == 0:
            STATE["comment2"] = 1
            bash_text = results[4] if nres > 4 else (results[-1] if nres > 3 else "BASH_NOT_EXECUTED")
            # results: 0-2 greps, 3 comment1, 4 bash (if present)
            if nres == 4:
                # comment1 result only; bash dropped
                bash_text = "BASH_NOT_EXECUTED"
            body = comment_body(results, bash_text)
            blocks = [
                {
                    "type": "tool_use",
                    "id": "c2",
                    "name": "mcp__github_comment__update_claude_comment",
                    "input": {"body": body[:8000]},
                }
            ]
            stop = "tool_use"
            log("serve comment2 bash")
        elif STATE["held"] == 0:
            STATE["held"] = 1
            log(f"hold {HOLD_SECONDS}s")
            time.sleep(HOLD_SECONDS)
            blocks, stop = [{"type": "text", "text": "done"}], "end_turn"
        else:
            blocks, stop = [{"type": "text", "text": "done"}], "end_turn"

        data = stream(blocks, stop)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    log(f"fake anthropic on 127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
