"""Reporters: terminal table and JSON output for run results."""
from __future__ import annotations

import json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _mark(r: dict) -> str:
    if r["pwned"]:
        return "PWNED  "
    if r.get("blocked"):
        return "BLOCKED"
    if r.get("inconclusive"):
        return "INCONCL"
    return "RESIST "


def render_terminal(results: list[dict]) -> str:
    lines = []
    pwned_count = sum(1 for r in results if r["pwned"])
    blocked_count = sum(1 for r in results if r.get("blocked") and not r["pwned"])
    inconcl_count = sum(1 for r in results if r.get("inconclusive"))
    lines.append(f"\npoisonkit results: {pwned_count}/{len(results)} attacks succeeded (agent pwned)")
    if blocked_count:
        defs = sorted({d for r in results for d in r.get("defenses", [])})
        lines.append(f"  {blocked_count} blocked by defenses ({', '.join(defs)})")
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
        for i in r.get("interventions", []):
            lines.append(f"        [defense:{i['defense']}] {i['action']}: {i.get('detail', '')}")
    lines.append("=" * 72)
    return "\n".join(lines)


def render_json(results: list[dict]) -> str:
    return json.dumps(results, indent=2)


def render_benign_terminal(results: list[dict]) -> str:
    lines = []
    ok = sum(1 for r in results if r["success"])
    fp = sum(1 for r in results if r.get("false_positive"))
    lines.append(f"\npoisonkit benign corpus: {ok}/{len(results)} tasks succeeded")
    if fp:
        lines.append(f"  {fp} false positive(s) — a defense fired on legitimate input")
    lines.append("=" * 72)
    for r in results:
        mark = "OK  " if r["success"] else "FAIL"
        fpmark = " [FALSE-POSITIVE]" if r.get("false_positive") else ""
        lines.append(f"[{mark}]{fpmark} {r['scenario']}: {r['title']} "
                     f"({r.get('tool_calls', '?')} tool calls)")
        for f in r["findings"]:
            fmark = "pass" if f["passed"] else "FAIL"
            lines.append(f"        ({fmark}) {f['label']}")
        for i in r.get("interventions", []):
            lines.append(f"        [defense:{i['defense']}] {i['action']}: {i.get('detail', '')}")
    lines.append("=" * 72)
    return "\n".join(lines)


def render_benign_json(results: list[dict]) -> str:
    return json.dumps(results, indent=2)
