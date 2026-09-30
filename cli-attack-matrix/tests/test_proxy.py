#!/usr/bin/env python3
"""test_proxy.py: unit tests for the sys-canary planting logic (no LLM, no network).

Covers the reviewer's requirements:
  * Responses API (/v1/responses) "instructions" channel is planted into
  * the proxy NEVER synthesizes a system channel when the product sends none
  * plant telemetry records planted / no_system_channel / unrecognized_shape
"""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVERS = os.path.join(os.path.dirname(HERE), "drivers")
sys.path.insert(0, DRIVERS)

import or_proxy  # noqa: E402

CANARY = "pk_syscanary_test"
MARKER = f"[Internal reference: {CANARY}]"


def plant(body_obj, path):
    body = json.dumps(body_obj).encode()
    or_proxy.SYS_CANARY = CANARY
    try:
        new_body, status, _shape = or_proxy._plant_sys_canary(body, path)
        return new_body, status
    finally:
        or_proxy.SYS_CANARY = None


def plant_shape(body_obj, path):
    """(new_body, status, shape) -- for shape-category assertions."""
    body = json.dumps(body_obj).encode()
    or_proxy.SYS_CANARY = CANARY
    try:
        return or_proxy._plant_sys_canary(body, path)
    finally:
        or_proxy.SYS_CANARY = None


class TestChatCompletionsPlanting(unittest.TestCase):
    def test_system_message_gets_marker(self):
        new_body, status = plant(
            {"model": "m", "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "hi"}]},
            "/v1/chat/completions")
        self.assertEqual(status, "planted")
        payload = json.loads(new_body)
        self.assertIn(MARKER, payload["messages"][0]["content"])
        self.assertIn("You are helpful.", payload["messages"][0]["content"])

    def test_no_system_message_is_not_synthesized(self):
        original = {"model": "m", "messages": [
            {"role": "user", "content": "hi"}]}
        new_body, status = plant(original, "/v1/chat/completions")
        self.assertEqual(status, "no_system_channel")
        # Body passes through byte-identical: no channel was invented.
        self.assertEqual(json.loads(new_body), original)


class TestResponsesPlanting(unittest.TestCase):
    def test_instructions_string_gets_marker(self):
        new_body, status = plant(
            {"model": "m", "instructions": "You are Codex.",
             "input": [{"role": "user", "content": "hi"}]},
            "/v1/responses")
        self.assertEqual(status, "planted")
        payload = json.loads(new_body)
        self.assertIn(MARKER, payload["instructions"])
        self.assertIn("You are Codex.", payload["instructions"])

    def test_instructions_list_gets_marker_block(self):
        new_body, status = plant(
            {"model": "m",
             "instructions": [{"type": "input_text", "text": "Be brief."}]},
            "/v1/responses")
        self.assertEqual(status, "planted")
        payload = json.loads(new_body)
        self.assertTrue(any(MARKER in b.get("text", "")
                            for b in payload["instructions"]))

    def test_developer_message_in_input_gets_marker(self):
        new_body, status = plant(
            {"model": "m",
             "input": [{"role": "developer", "content": "Dev notes."},
                       {"role": "user", "content": "hi"}]},
            "/v1/responses")
        self.assertEqual(status, "planted")
        payload = json.loads(new_body)
        self.assertIn(MARKER, payload["input"][0]["content"])

    def test_no_channel_is_not_synthesized(self):
        original = {"model": "m",
                    "input": [{"role": "user", "content": "hi"}]}
        new_body, status = plant(original, "/v1/responses")
        self.assertEqual(status, "no_system_channel")
        self.assertEqual(json.loads(new_body), original)


class TestAnthropicPlanting(unittest.TestCase):
    def test_system_string_gets_marker(self):
        new_body, status = plant(
            {"model": "m", "system": "You are Claude.",
             "messages": [{"role": "user", "content": "hi"}]},
            "/api/messages")
        self.assertEqual(status, "planted")
        self.assertIn(MARKER, json.loads(new_body)["system"])

    def test_system_block_list_gets_marker(self):
        new_body, status = plant(
            {"model": "m",
             "system": [{"type": "text", "text": "You are Claude."}]},
            "/api/messages")
        self.assertEqual(status, "planted")
        payload = json.loads(new_body)
        self.assertTrue(any(MARKER in b.get("text", "")
                            for b in payload["system"]))

    def test_missing_system_is_not_synthesized(self):
        original = {"model": "m",
                    "messages": [{"role": "user", "content": "hi"}]}
        new_body, status = plant(original, "/api/messages")
        self.assertEqual(status, "no_system_channel")
        self.assertEqual(json.loads(new_body), original)


class TestUnrecognizedShapes(unittest.TestCase):
    def test_invalid_json_passes_through(self):
        or_proxy.SYS_CANARY = CANARY
        try:
            new_body, status, shape = or_proxy._plant_sys_canary(
                b"not json", "/v1/chat/completions")
        finally:
            or_proxy.SYS_CANARY = None
        self.assertEqual(status, "unrecognized_shape")
        self.assertEqual(shape, "")
        self.assertEqual(new_body, b"not json")

    def test_unknown_v1_shape_passes_through(self):
        new_body, status = plant({"model": "m", "foo": 1},
                                 "/v1/chat/completions")
        self.assertEqual(status, "unrecognized_shape")
        self.assertEqual(json.loads(new_body), {"model": "m", "foo": 1})


class TestShapeCategories(unittest.TestCase):
    """The telemetry must record the exact request-shape category the
    sentinel was planted into (reviewer checklist)."""

    def test_chat_system_message(self):
        _, status, shape = plant_shape(
            {"model": "m", "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "hi"}]},
            "/v1/chat/completions")
        self.assertEqual(status, "planted")
        self.assertEqual(shape, "chat.system_message")

    def test_responses_instructions_string(self):
        _, status, shape = plant_shape(
            {"model": "m", "instructions": "sys",
             "input": [{"role": "user", "content": "hi"}]},
            "/v1/responses")
        self.assertEqual(status, "planted")
        self.assertEqual(shape, "responses.instructions")

    def test_responses_input_developer(self):
        _, status, shape = plant_shape(
            {"model": "m", "input": [
                {"role": "developer", "content": "sys"},
                {"role": "user", "content": "hi"}]},
            "/v1/responses")
        self.assertEqual(status, "planted")
        self.assertEqual(shape, "responses.input.developer")

    def test_anthropic_system(self):
        _, status, shape = plant_shape(
            {"model": "m", "system": "sys",
             "messages": [{"role": "user", "content": "hi"}]},
            "/api/messages")
        self.assertEqual(status, "planted")
        self.assertEqual(shape, "anthropic.system")

    def test_no_channel_shape_empty(self):
        _, status, shape = plant_shape(
            {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
            "/v1/chat/completions")
        self.assertEqual(status, "no_system_channel")
        self.assertEqual(shape, "")


class TestPlantTelemetry(unittest.TestCase):
    def test_log_plant_appends_jsonl(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        orig = or_proxy.PLANT_LOG
        or_proxy.PLANT_LOG = path
        try:
            or_proxy._log_plant("/v1/responses", "planted")
            or_proxy._log_plant("/v1/responses", "no_system_channel")
        finally:
            or_proxy.PLANT_LOG = orig
        with open(path) as f:
            recs = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(recs), 2)
        self.assertTrue(recs[0]["planted"])
        self.assertEqual(recs[0]["status"], "planted")
        self.assertFalse(recs[1]["planted"])
        self.assertEqual(recs[1]["status"], "no_system_channel")


if __name__ == "__main__":
    unittest.main()
