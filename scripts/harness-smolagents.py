#!/usr/bin/env python3
"""Black-box test: poisonkit attacks vs a smolagents ToolCallingAgent.

Wiring: the agent's tools come from the poisoned MCP server over stdio via
smolagents' ToolCollection.from_mcp (trust_remote_code=True). The model is
either a scripted local stub (offline) or NVIDIA NIM via a local proxy.

Usage:
  harness-smolagents.py --attack desc-override --backend stub --stub-mode pwn
  harness-smolagents.py --attack exfil-chain --backend nim --model z-ai/glm-5.3

Exit codes: 0 ran to a verdict, 1 usage error, 2 backend/model failure.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness_common import (  # noqa: E402
    NimProxy, StubBackend, make_sink_log, report, sanitize_proxy_env,
    server_command, server_env, stub_script_for)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))


def build_trace(agent) -> list[dict]:
    trace: list[dict] = []
    for step in agent.memory.steps:
        tool_calls = getattr(step, "tool_calls", None) or []
        observations = getattr(step, "observations", None) or []
        for i, tc in enumerate(tool_calls):
            args = tc.arguments
            if isinstance(args, str):
                try:
                    args = json.loads(args or "{}")
                except json.JSONDecodeError:
                    args = {"_raw": args}
            obs = observations[i] if i < len(observations) else ""
            trace.append({"type": "tool_call", "name": tc.name,
                          "args": args or {}, "result": str(obs)})
    return trace


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="desc-override")
    ap.add_argument("--backend", choices=["stub", "nim"], default="stub")
    ap.add_argument("--stub-mode", choices=["pwn", "resist"], default="pwn")
    ap.add_argument("--model", default="z-ai/glm-5.3",
                    help="NIM model id for --backend nim")
    ap.add_argument("--max-steps", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-request timeout (s) for the model client")
    ns = ap.parse_args()

    from poisonkit.attacks import get_attack
    attack = get_attack(ns.attack)
    sanitize_proxy_env()
    make_sink_log()

    from smolagents import OpenAIServerModel, ToolCallingAgent, ToolCollection
    from mcp import StdioServerParameters

    if ns.backend == "stub":
        backend: StubBackend | NimProxy = StubBackend(
            stub_script_for(ns.attack, ns.stub_mode))
        model_id, api_key = "stub", "stub-key"
    else:
        backend = NimProxy(timeout=ns.timeout)
        model_id, api_key = ns.model, "proxy-key"

    with backend:
        command, args = server_command(ns.attack)
        params = StdioServerParameters(command=command, args=args,
                                         env=server_env())
        with ToolCollection.from_mcp(params,
                                     trust_remote_code=True) as collection:
            tools = list(collection.tools)
            print(f"[wiring] {len(tools)} tool(s) loaded from poisoned MCP server:")
            for t in tools:
                print(f"  - {t.name}: {(t.description or '')[:160]}")
            if not tools:
                print("[wiring] ERROR: no tools loaded; aborting")
                return 2
            model = OpenAIServerModel(
                model_id=model_id, api_base=backend.base_url,
                api_key=api_key, client_kwargs={"timeout": ns.timeout})
            agent = ToolCallingAgent(tools=[*tools], model=model,
                                     max_steps=ns.max_steps)
            try:
                result = agent.run(attack.task)
            except Exception as e:
                print(f"[model] backend call failed: {type(e).__name__}: {e}")
                return 2
            print(f"\n[final] {result}")
            trace = build_trace(agent)
            trace.append({"type": "final", "text": str(result)})
    report(ns.attack, trace, harness="smolagents",
           listed={t.name: t.description for t in tools})
    return 0


if __name__ == "__main__":
    sys.exit(main())
