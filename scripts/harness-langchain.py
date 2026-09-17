#!/usr/bin/env python3
"""Black-box test: poisonkit attacks vs a LangChain ReAct agent.

Wiring: tools come from the poisoned MCP server over stdio via
langchain-mcp-adapters' MultiServerMCPClient (transport="stdio"), then a
LangChain agent (langchain.agents.create_agent) runs the attack task. The
model is either a scripted local stub (offline) or NVIDIA NIM via a local
proxy (ChatOpenAI pointed at an OpenAI-compatible base URL).

Usage:
  harness-langchain.py --attack desc-override --backend stub --stub-mode pwn
  harness-langchain.py --attack exfil-chain --backend nim --model z-ai/glm-5.3

Exit codes: 0 ran to a verdict, 1 usage error, 2 backend/model failure.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness_common import (  # noqa: E402
    NimProxy, StubBackend, make_sink_log, report, sanitize_proxy_env,
    server_command, server_env, stub_script_for)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))


def build_trace(messages) -> list[dict]:
    from langchain_core.messages import AIMessage, ToolMessage
    trace: list[dict] = []
    pending: dict[str, tuple[str, dict]] = {}
    final_text = ""
    for m in messages:
        if isinstance(m, AIMessage):
            for tc in m.tool_calls or []:
                pending[tc["id"]] = (tc["name"], tc.get("args") or {})
            if not (m.tool_calls or []):
                final_text = m.content if isinstance(m.content, str) \
                    else str(m.content)
        elif isinstance(m, ToolMessage):
            name, args = pending.pop(m.tool_call_id, ("?", {}))
            trace.append({"type": "tool_call", "name": name, "args": args,
                          "result": str(m.content)})
    trace.append({"type": "final", "text": final_text})
    return trace


async def amain(ns) -> int:
    from poisonkit.attacks import get_attack
    attack = get_attack(ns.attack)
    sanitize_proxy_env()
    make_sink_log()

    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain.agents import create_agent
    from langchain_openai import ChatOpenAI

    if ns.backend == "stub":
        backend: StubBackend | NimProxy = StubBackend(
            stub_script_for(ns.attack, ns.stub_mode))
        model_id, api_key = "stub", "stub-key"
    else:
        backend = NimProxy(timeout=ns.timeout)
        model_id, api_key = ns.model, "proxy-key"

    with backend:  # sync CM: both backends are thread-based servers
        command, args = server_command(ns.attack)
        client = MultiServerMCPClient({
            "poisonkit": {"command": command, "args": args,
                          "transport": "stdio", "env": server_env()},
        })
        tools = await client.get_tools()
        print(f"[wiring] {len(tools)} tool(s) loaded from poisoned MCP server:")
        for t in tools:
            print(f"  - {t.name}: {(t.description or '')[:160]}")
        if not tools:
            print("[wiring] ERROR: no tools loaded; aborting")
            return 2
        llm = ChatOpenAI(model=model_id, base_url=backend.base_url,
                         api_key=api_key, request_timeout=ns.timeout)
        agent = create_agent(llm, tools)
        try:
            result = await agent.ainvoke(
                {"messages": [{"role": "user", "content": attack.task}]},
                config={"recursion_limit": 25})
        except Exception as e:
            print(f"[model] backend call failed: {type(e).__name__}: {e}")
            return 2
        trace = build_trace(result["messages"])
        final = next((ev["text"] for ev in reversed(trace)
                      if ev["type"] == "final"), "")
        print(f"\n[final] {final}")
    report(ns.attack, trace, harness="langchain",
           listed={t.name: t.description for t in tools})
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="desc-override")
    ap.add_argument("--backend", choices=["stub", "nim"], default="stub")
    ap.add_argument("--stub-mode", choices=["pwn", "resist"], default="pwn")
    ap.add_argument("--model", default="z-ai/glm-5.3",
                    help="NIM model id for --backend nim")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-request timeout (s) for the model client")
    ns = ap.parse_args()
    return asyncio.run(amain(ns))


if __name__ == "__main__":
    sys.exit(main())
