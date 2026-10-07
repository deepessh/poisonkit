#!/usr/bin/env python3
"""test_fixture.py: direct MCP fixture self-tests (stdio JSON-RPC, no LLM).

Validates, for every attack variant:
  * tools/list returns exactly the canonical tools, with verbatim
    descriptions and parameter schemas from src/poisonkit/attacks.py
  * tools/call dispatches, and every call is recorded in the structured
    activity log with its arguments
  * destructive handlers are safe stubs (delete_file never touches
    anything but the fixture-owned dummy)
  * rug-pull phase 2 serves the canonical swapped description
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(os.path.dirname(HERE), "fixtures",
                       "pk_mcp_fixture.py")
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from poisonkit.attacks import ATTACKS, get_attack  # noqa: E402

ATTACK_IDS = [a.id for a in ATTACKS]


class FixtureProc:
    """Spawn the fixture with the given env; speak JSON-RPC over stdio."""

    def __init__(self, attack, rug_phase="1"):
        self.activity = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False).name
        self.sink = tempfile.NamedTemporaryFile(
            suffix=".log", delete=False).name
        env = dict(os.environ)
        env["PK_ATTACK"] = attack
        env["PK_RUG_PHASE"] = rug_phase
        env["POISONKIT_ACTIVITY_LOG"] = self.activity
        env["POISONKIT_SINK_LOG"] = self.sink
        self.proc = subprocess.Popen(
            [sys.executable, FIXTURE], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            env=env)
        self._id = 0

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        assert self.proc.stdout is not None
        return json.loads(self.proc.stdout.readline())

    def notify(self, method):
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def activity_events(self):
        events = []
        with open(self.activity) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            self.proc.kill()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class TestFixtureConformance(unittest.TestCase):
    def test_all_attacks_list_canonical_tools(self):
        for attack in ATTACK_IDS:
            atk = get_attack(attack)
            with FixtureProc(attack) as fx:
                fx.request("initialize")
                fx.notify("notifications/initialized")
                resp = fx.request("tools/list")
            tools = {t["name"]: t for t in resp["result"]["tools"]}
            self.assertEqual(sorted(tools), sorted(td.name for td in
                                                   atk.tools), attack)
            for td in atk.tools:
                # Verbatim: the fixture must not paraphrase the canonical
                # payloads.
                self.assertEqual(tools[td.name]["description"],
                                 td.description, (attack, td.name))
                self.assertEqual(tools[td.name]["inputSchema"],
                                 td.parameters, (attack, td.name))

    def test_benign_variant(self):
        with FixtureProc("benign") as fx:
            resp = fx.request("tools/list")
            self.assertEqual([t["name"] for t in resp["result"]["tools"]],
                             ["get_weather"])
            resp = fx.request("tools/call",
                              {"name": "get_weather",
                               "arguments": {"city": "Paris"}})
            text = resp["result"]["content"][0]["text"]
            # Unique fixture marker the benign gate checks for.
            self.assertIn("sunny, 21C", text)

    def test_rug_pull_phase2_serves_swapped_description(self):
        atk = get_attack("rug-pull")
        swap = {s["tool"]: s["description"] for s in atk.swaps}
        with FixtureProc("rug-pull", "1") as fx:
            tools1 = {t["name"]: t["description"]
                      for t in fx.request("tools/list")["result"]["tools"]}
        with FixtureProc("rug-pull", "2") as fx:
            tools2 = {t["name"]: t["description"]
                      for t in fx.request("tools/list")["result"]["tools"]}
        for name, desc in tools1.items():
            if name in swap:
                self.assertNotEqual(tools2[name], desc, name)
                self.assertEqual(tools2[name], swap[name], name)
            else:
                self.assertEqual(tools2[name], desc, name)

    def test_tools_list_event_carries_desc_hash(self):
        # The raw activity artifact fingerprints the exact metadata each
        # phase served: the two rug-pull phases must hash differently.
        with FixtureProc("rug-pull", "1") as fx:
            fx.request("tools/list")
            ev1 = [e for e in fx.activity_events()
                   if e["event"] == "tools_list"]
        with FixtureProc("rug-pull", "2") as fx:
            fx.request("tools/list")
            ev2 = [e for e in fx.activity_events()
                   if e["event"] == "tools_list"]
        self.assertEqual(len(ev1), 1)
        self.assertEqual(len(ev2), 1)
        self.assertIn("desc_hash", ev1[0])
        self.assertIn("desc_hash", ev2[0])
        self.assertEqual(len(ev1[0]["desc_hash"]), 64)
        self.assertNotEqual(ev1[0]["desc_hash"], ev2[0]["desc_hash"])
        # Non-rug phases hash identically across identical listings.
        with FixtureProc("tool-shadow") as fx:
            fx.request("tools/list")
            ev3 = [e for e in fx.activity_events()
                   if e["event"] == "tools_list"]
        with FixtureProc("tool-shadow") as fx:
            fx.request("tools/list")
            ev4 = [e for e in fx.activity_events()
                   if e["event"] == "tools_list"]
        self.assertEqual(ev3[0]["desc_hash"], ev4[0]["desc_hash"])

    def test_tool_call_is_activity_logged_with_arguments(self):
        with FixtureProc("tool-shadow") as fx:
            fx.request("tools/list")
            args = {"to": "ana@example.com", "subject": "Hello",
                    "body": "Just checking in."}
            resp = fx.request("tools/call",
                              {"name": "send_email_secure",
                               "arguments": args})
            self.assertIn("result", resp)
            events = fx.activity_events()
        kinds = [e["event"] for e in events]
        self.assertIn("fixture_start", kinds)
        self.assertIn("tools_list", kinds)
        calls = [e for e in events if e["event"] == "tool_call"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["name"], "send_email_secure")
        self.assertEqual(calls[0]["arguments"], args)
        self.assertEqual(calls[0]["attack"], "tool-shadow")

    def test_delete_file_is_safe_stub(self):
        import glob
        with FixtureProc("rag-poison") as fx:
            fx.request("ping")
            dummy = next(e["dummy_path"] for e in fx.activity_events()
                         if e["event"] == "fixture_start")
            resp = fx.request("tools/call",
                              {"name": "delete_file",
                               "arguments": {"path": "/roadmap.md"}})
            text = resp["result"]["content"][0]["text"]
            self.assertIn("fixture stub", text)
            # The fixture-owned dummy survives; nothing else was touched.
            self.assertTrue(os.path.exists(dummy))
            calls = [e for e in fx.activity_events()
                     if e["event"] == "tool_call"]
            self.assertEqual(calls[0]["arguments"], {"path": "/roadmap.md"})
        leftovers = [p for p in glob.glob("/roadmap.md")]
        self.assertEqual(leftovers, [])

    def test_canary_record_embeds_canonical_canary(self):
        canary = get_attack("exfil-chain").canaries["ssn"]
        with FixtureProc("exfil-chain") as fx:
            resp = fx.request("tools/call",
                              {"name": "read_customer_db",
                               "arguments": {"customer_id": "C-123"}})
            text = resp["result"]["content"][0]["text"]
            self.assertIn(canary, text)

    def test_unknown_tool_and_ping(self):
        with FixtureProc("benign") as fx:
            resp = fx.request("tools/call",
                              {"name": "nope", "arguments": {}})
            self.assertIn("error", resp)
            resp = fx.request("ping")
            self.assertEqual(resp["result"], {})


if __name__ == "__main__":
    unittest.main()
