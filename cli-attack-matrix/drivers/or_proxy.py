#!/usr/bin/env python3
"""or_proxy.py: localhost forward proxy that injects the OpenRouter credential.

Coding CLIs (codex, claude, copilot) make their own HTTPS
requests and each wants a base URL + API key. Instead of placing the raw
OpenRouter key in env vars or config files, point the CLIs at this proxy:

    /v1/* -> https://openrouter.ai/api/v1/*   (OpenAI-compatible path:
                                               codex, copilot)
    /api/* -> https://openrouter.ai/api/*     (Anthropic-compatible path:
                                               claude code via
                                               ANTHROPIC_BASE_URL)

The proxy attaches the stored ``custom.openrouter`` credential as an authd
surrogate on every outbound request; authd/Sentinel swaps the surrogate for
the real key in flight. The raw key never appears in env, config, logs, or
disk. Any inbound Authorization / x-api-key header (drivers use a dummy
value, since some CLIs require a non-empty key) is stripped.

Stdlib only. Upstream responses are buffered, not streamed -- fine for the
short prompts used in test runs; not suitable for long interactive use.

Protocol:
    $ python3 or_proxy.py [--port 0]
    prints "OR_PROXY_PORT=<n>" on stdout, then serves until killed.
"""

from __future__ import annotations

import argparse
import http.server
import os
import socketserver
import sys
import time
import urllib.request

try:  # Hatch VM: attach the stored credential as an authd surrogate
    sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
    from dynamic_credentials import (
        DynamicCredentialError,
        add_surrogate_to_request,
        read_response_body,
    )
    _USE_SURROGATE = True
except ImportError:  # elsewhere: use OPENROUTER_API_KEY from the environment
    _USE_SURROGATE = False
    DynamicCredentialError = RuntimeError

    def read_response_body(resp):
        return resp.read()

UPSTREAM = "https://openrouter.ai"
CREDENTIAL_NAME = "custom.openrouter"
ALLOWED_HOSTS = ["openrouter.ai"]
UPSTREAM_TIMEOUT = 600

# Hop-by-hop / identity headers that must not be forwarded upstream.
STRIP_REQUEST_HEADERS = {
    "host", "authorization", "x-api-key", "proxy-authorization",
    "connection", "keep-alive", "proxy-authenticate", "proxy-connection",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
}
STRIP_RESPONSE_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-connection",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
}

MAX_BODY = 64 * 1024 * 1024


def map_path(path: str) -> str | None:
    """Map a local path to its upstream OpenRouter path."""
    if path.startswith("/v1/") or path == "/v1":
        return "/api" + path
    if path.startswith("/api/") or path == "/api":
        return path
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OrProxy/1.0"

    def log_message(self, fmt, *args):  # keep stdout clean for PORT line
        sys.stderr.write(
            "[or_proxy %s] %s %s\n"
            % (time.strftime("%H:%M:%S"), self.command, self.path)
        )

    def _forward(self):
        upstream_path = map_path(self.path.split("?", 1)[0])
        if upstream_path is None:
            self.send_error(404, "or_proxy: unknown path prefix")
            return
        if "?" in self.path:
            upstream_path += "?" + self.path.split("?", 1)[1]
        url = UPSTREAM + upstream_path

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self.send_error(413, "or_proxy: body too large")
            return
        body = self.rfile.read(length) if length else None

        req = urllib.request.Request(url, data=body, method=self.command)
        for key, value in self.headers.items():
            if key.lower() in STRIP_REQUEST_HEADERS:
                continue
            req.add_header(key, value)
        req.add_header("HTTP-Referer", "https://github.com/deepessh/poisonkit")
        req.add_header("X-Title", "poisonkit-cli-matrix")
        if _USE_SURROGATE:
            try:
                add_surrogate_to_request(
                    req, CREDENTIAL_NAME, allowed_hosts=ALLOWED_HOSTS)
            except DynamicCredentialError as e:
                self.send_error(502, f"or_proxy: credential error: {e}")
                return
        else:
            api_key = os.environ.get("OPENROUTER_API_KEY", "")
            if not api_key:
                self.send_error(502, "or_proxy: set OPENROUTER_API_KEY")
                return
            req.add_header("Authorization", f"Bearer {api_key}")

        try:
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
                status, resp_body = resp.status, read_response_body(resp)
                resp_headers = list(resp.headers.items())
        except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
            status = e.code
            resp_body = e.read(MAX_BODY)
            resp_headers = list(e.headers.items())
        except Exception as e:  # noqa: BLE001 - report upstream failures
            self.send_error(502, f"or_proxy: upstream error: {e!r}")
            return

        self.send_response(status)
        for key, value in resp_headers:
            if key.lower() in STRIP_RESPONSE_HEADERS:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)
        sys.stderr.write(
            "[or_proxy %s] -> %s %d (%d bytes)\n"
            % (time.strftime("%H:%M:%S"), upstream_path.split("?")[0],
               status, len(resp_body))
        )

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_DELETE = _forward
    do_PATCH = _forward


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=0)
    ns = p.parse_args()

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    srv = Server(("127.0.0.1", ns.port), Handler)
    port = srv.server_address[1]
    print(f"OR_PROXY_PORT={port}", flush=True)
    sys.stderr.write(f"[or_proxy] listening on 127.0.0.1:{port}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
