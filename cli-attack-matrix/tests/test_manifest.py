#!/usr/bin/env python3
"""test_manifest.py: immutable run-manifest tests (no LLM, no network).

Covers: classify_with_reasons return contract (timeout / nonzero exit /
benign control / no-engagement), build_manifest fields (git SHA, CLI
version, model slug, ISO timestamps, artifact paths, oracle reasons),
and save_artifacts copying the proxy plant log into the results dir.
"""

import datetime
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVERS = os.path.join(os.path.dirname(HERE), "drivers")
sys.path.insert(0, DRIVERS)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)),
                                "src"))

import run_matrix  # noqa: E402
from cli_drivers import (  # noqa: E402
    RunResult,
    classify_with_reasons,
    cli_version,
    git_sha,
)


def _result(**kw):
    base = dict(cli="codex", prompt="p", model="m", attack="benign",
                transcript="", stderr="", exit_code=0, duration_s=0.0,
                timed_out=False, workdir="", notes=[])
    base.update(kw)
    return RunResult(**base)


class ClassifyWithReasonsTests(unittest.TestCase):
    def test_timeout_returns_reasons(self):
        v, reasons = classify_with_reasons(_result(timed_out=True))
        self.assertEqual(v, "inconclusive")
        self.assertTrue(reasons)

    def test_nonzero_exit_returns_reasons(self):
        v, reasons = classify_with_reasons(_result(exit_code=1))
        self.assertEqual(v, "inconclusive")
        self.assertTrue(any("exit_code" in r for r in reasons))

    def test_benign_no_engagement_is_inconclusive(self):
        v, reasons = classify_with_reasons(_result())
        self.assertEqual(v, "inconclusive")
        self.assertTrue(reasons)

    def test_benign_engaged_is_resist(self):
        fd, ap = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"event": "tools_list",
                                "tools": ["get_weather"]}) + "\n")
        r = _result(notes=[f"activity_log={ap}"])
        v, reasons = classify_with_reasons(r)
        os.unlink(ap)
        self.assertEqual(v, "resist")
        self.assertTrue(reasons)


class ManifestTests(unittest.TestCase):
    def test_manifest_fields(self):
        out = tempfile.mkdtemp()
        t0, t1 = 1_700_000_000.0, 1_700_000_060.5
        m = run_matrix.build_manifest(
            "codex", "openai/gpt-6-luna", out, ["cell1"], t0, t1,
            ["reason one"])
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}|unknown", m["git_sha"]),
                        m["git_sha"])
        self.assertEqual(m["cli"], "codex")
        self.assertTrue(m["cli_version"])
        self.assertEqual(m["model"], "openai/gpt-6-luna")
        s = datetime.datetime.fromisoformat(m["started_at"])
        e = datetime.datetime.fromisoformat(m["ended_at"])
        self.assertLess(s, e)
        arts = m["artifacts"]["cell1"]
        self.assertEqual(
            set(arts),
            {"transcript", "stderr", "activity_log", "sink_log",
             "plant_log"})
        self.assertTrue(all(p.startswith(out) for p in arts.values()))
        self.assertEqual(m["oracle_reasons"], ["reason one"])

    def test_save_artifacts_copies_plant_log(self):
        out = tempfile.mkdtemp()
        fd, pl = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w") as f:
            f.write('{"planted": true, "status": "planted"}\n')
        r = _result(transcript="t" * 50, notes=[f"plant_log={pl}"])
        run_matrix.save_artifacts(out, "cell1", r)
        dst = os.path.join(out, "cell1-plant.jsonl")
        self.assertTrue(os.path.exists(dst))
        self.assertIn('"planted": true', open(dst).read())
        os.unlink(pl)


class EnvInfoTests(unittest.TestCase):
    def test_cli_version_unknown_for_missing_binary(self):
        self.assertEqual(cli_version("definitely-not-a-real-cli-xyz"),
                         "unknown")

    def test_git_sha_shape(self):
        sha = git_sha()
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}|unknown", sha), sha)


class CopilotSessionIdTests(unittest.TestCase):
    def test_parses_resume_id(self):
        from cli_drivers import _copilot_session_id  # noqa: E402
        self.assertEqual(
            _copilot_session_id(
                "Resume     copilot --resume=f9a69555-d12f-4ca4-bf5b-"
                "a5da9b12478d"),
            "f9a69555-d12f-4ca4-bf5b-a5da9b12478d")

    def test_absent_returns_none(self):
        from cli_drivers import _copilot_session_id  # noqa: E402
        self.assertIsNone(_copilot_session_id("no footer here"))
        self.assertIsNone(_copilot_session_id(""))


if __name__ == "__main__":
    unittest.main()


class GitShaTests(unittest.TestCase):
    def test_git_sha_returns_real_sha_in_repo(self):
        import cli_drivers
        cli_drivers._git_sha_cache = None
        try:
            sha = cli_drivers.git_sha()
        finally:
            cli_drivers._git_sha_cache = None
        self.assertNotEqual(sha, "unknown")
        self.assertRegex(sha, r"^[0-9a-f]{40}$")
