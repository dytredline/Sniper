import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ssllabs_live import MAX_CALLS, run_ssllabs_live


class SsllabsAuthorizedRuntimeTests(unittest.TestCase):
    def test_synthetic_upstream_drives_real_bounded_durable_state_machine(self):
        calls = []
        reports = [
            {"host": "example.com", "status": "IN_PROGRESS"},
            {"host": "example.com", "status": "READY", "endpoints": [{"grade": "A"}]},
        ]

        def transport(url, headers, timeout_seconds, allow_redirects):
            calls.append((url, headers, timeout_seconds, allow_redirects))
            return 200, {}, reports.pop(0)

        with tempfile.TemporaryDirectory(dir=Path.home()) as raw:
            state_dir = Path(raw) / "ssllabs-rate"
            state_dir.mkdir(mode=0o700)
            with mock.patch.dict(
                os.environ, {"SNIPER_SSLLABS_RATE_STATE_DIR": str(state_dir)}, clear=False
            ):
                result = run_ssllabs_live(
                    "example.com",
                    "registered@example.com",
                    transport=transport,
                    sleep=lambda _seconds: None,
                )
            state = json.loads((state_dir / "rate.json").read_text(encoding="utf-8"))

        self.assertEqual(result["assessment_status"], "READY")
        self.assertEqual(result["grade_counts"]["A"], 1)
        self.assertEqual(len(calls), 2)
        self.assertLessEqual(len(calls), MAX_CALLS)
        first = urlsplit(calls[0][0])
        second = urlsplit(calls[1][0])
        self.assertEqual((first.scheme, first.hostname, first.path), (
            "https", "api.ssllabs.com", "/api/v4/analyze"
        ))
        self.assertEqual(parse_qs(first.query), {
            "host": ["example.com"], "publish": ["off"],
            "all": ["done"], "startNew": ["on"],
        })
        self.assertEqual(parse_qs(second.query), {
            "host": ["example.com"], "publish": ["off"], "all": ["done"],
        })
        self.assertEqual(calls[0][1]["email"], "registered@example.com")
        self.assertIs(calls[0][3], False)
        self.assertEqual(state["inflight"], {})
        self.assertIn("example.com", state["last_start"])


if __name__ == "__main__":
    unittest.main()
