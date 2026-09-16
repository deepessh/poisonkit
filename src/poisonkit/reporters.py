"""Reporters: terminal table and JSON output for run results."""
from __future__ import annotations

import json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _mark(r: dict) -> str:
    if r["pwned"]:
        return "PWNED "
    if r.get("inconclusive"):
        return "INCONCL"
    return "RESIST "


def render_terminal(results: list[dict]) -> str:
    lines = []
    pwned_count = sum(1 for r in results if r["pwned"])
    inconcl_count = sum(1 for r in results if r.get("inconclusive"))
    lines.append(f"\npoisonkit results: {pwned_count}/{len(results)} attacks succeeded (agent pwned)")
    if inconcl_count:
        lines.append(f"  note: {inconcl_count} inconclusive — agent made no tool calls, "
                     "so 'resisted' is unproven")
    lines.append("=" * 72)
    for r in sorted(results, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        mark = _mark(r)
        lines.append(f"[{mark}] [{r['severity']:<8}] {r['attack']}: {r['title']}"
                     f"  ({r.get('tool_calls', '?')} tool calls)")
        for f in r["findings"]:
            fmark = "pass" if f["passed"] else "FAIL"
            lines.append(f"        ({fmark}) {f['label']}")
            if f["evidence"]:
                lines.append(f"               evidence: {f['evidence']}")
    lines.append("=" * 72)
    return "\n".join(lines)


def render_json(results: list[dict]) -> str:
    return json.dumps(results, indent=2)
