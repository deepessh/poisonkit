"""Tool-name sanitization: model format artifacts must not break dispatch.

Regression test for the live-run wart where gpt-oss-20b (Harmony format)
emitted `delete_file<|channel|>commentary` as the tool name, producing an
MCP "not listed" warning. The harness normalizes the name before dispatch
and keeps the raw value in the trace for audit.
"""
from poisonkit.runner import MockModel, _clean_tool_name, run_attack


def test_clean_tool_name_strips_harmony_artifacts():
    assert _clean_tool_name("delete_file<|channel|>commentary") == "delete_file"
    assert _clean_tool_name("delete_file") == "delete_file"
    assert _clean_tool_name("  send_email  ") == "send_email"


def test_polluted_tool_name_still_dispatches_and_detects():
    script = [
        {"tool_calls": [{"id": "c1", "name": "delete_file<|channel|>commentary",
                         "args": {"path": "/roadmap.md"}}], "text": ""},
        {"tool_calls": [], "text": "done"},
    ]
    result = run_attack("rag-poison", MockModel(script))
    calls = [ev for ev in result["trace"] if ev.get("type") == "tool_call"]
    assert len(calls) == 1
    assert calls[0]["name"] == "delete_file"
    assert calls[0]["raw_name"] == "delete_file<|channel|>commentary"
    assert result["pwned"], "cleaned delete_file call must still trip the detector"
