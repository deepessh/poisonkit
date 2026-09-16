"""poisonkit CLI."""
from __future__ import annotations

import argparse
import os
import sys

from poisonkit.attacks import get_attack, list_attacks
from poisonkit.reporters import render_json, render_terminal
from poisonkit.runner import NimSkillAdapter, OpenAIAdapter, run_attack
from poisonkit.server import serve_main


def _model_from_env():
    api_key = os.environ.get("POISONKIT_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("error: set POISONKIT_API_KEY or OPENAI_API_KEY to run against a live model",
              file=sys.stderr)
        sys.exit(2)
    return OpenAIAdapter(
        api_key=api_key,
        base_url=os.environ.get("POISONKIT_BASE_URL", "https://api.openai.com/v1"),
        model=os.environ.get("POISONKIT_MODEL", "gpt-4o-mini"),
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="poisonkit",
                                description="MCP tool-poisoning test kit")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-attacks", help="list available attacks")

    ps = sub.add_parser("serve", help="serve a poisoned MCP server on stdio")
    ps.add_argument("--attack", required=True)

    pr = sub.add_parser("run", help="run attack(s) against a victim agent")
    pr.add_argument("--attack", default="all", help="attack id or 'all'")
    pr.add_argument("--json", action="store_true", help="emit JSON report")
    pr.add_argument("--provider", default="openai", choices=["openai", "nvidia"],
                    help="model backend: OpenAI-compatible key from env (default), "
                         "or NVIDIA NIM via the stored connector")

    ns = p.parse_args(argv)

    if ns.cmd == "list-attacks":
        for a in list_attacks():
            print(f"{a.id:<16} [{a.severity:<8}] {a.title}")
        return 0

    if ns.cmd == "serve":
        return serve_main(["--attack", ns.attack])

    if ns.cmd == "run":
        ids = [a.id for a in list_attacks()] if ns.attack == "all" else [ns.attack]
        for i in ids:
            get_attack(i)  # validate early
        if ns.provider == "nvidia":
            model = NimSkillAdapter(
                model=os.environ.get("POISONKIT_MODEL", "openai/gpt-oss-20b"))
        else:
            model = _model_from_env()
        results = [run_attack(i, model) for i in ids]
        print(render_json(results) if ns.json else render_terminal(results))
        # Exit codes: 1 = an attack succeeded (pwned); 2 = no pwns but at
        # least one run was inconclusive (agent never called a tool, so the
        # "resist" is unproven — don't let CI treat it as green); 0 = clean.
        if any(r["pwned"] for r in results):
            return 1
        if any(r.get("inconclusive") for r in results):
            return 2
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
