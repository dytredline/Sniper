"""The local CLI lists only validated Nuclei aggregate journal records."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from nuclei_aggregate_history import AggregateHistoryJournal


APP = Path(__file__).resolve().parents[1]


class CliNucleiHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sniper-nuclei-history-")
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def cli(self, *options: str, script: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script or APP / "cli_reports.py"), "nuclei-history", *options],
            cwd=APP, capture_output=True, text=True, timeout=10,
        )

    def test_exact_redacted_runtime_result_and_recent_order(self) -> None:
        recent = [
            ("0123456789abcdef", {"state": "completed", "elapsed_seconds": 2.5,
                "record_count": 2, "severity_counts": {"critical": 1, "info": 1},
                "unique_template_count": 2, "report_sha256": "a" * 64}),
            ("fedcba9876543210", {"state": "failed", "elapsed_seconds": 0.25,
                "error_code": "nonzero_exit"}),
        ]
        AggregateHistoryJournal(self.data).save(recent)
        (self.data / "unrelated-private-input").write_text("PRIVATE_TARGET_SHOULD_NOT_APPEAR")
        result = self.cli("--data-dir", str(self.data))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [{"job_id": job_id, **entry} for job_id, entry in recent])
        self.assertNotIn("PRIVATE_TARGET_SHOULD_NOT_APPEAR", result.stdout)
        self.assertFalse((self.data / "sniper.db").exists())

    def test_missing_journal_is_empty_and_does_not_create_database(self) -> None:
        result = self.cli("--data-dir", str(self.data))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])
        self.assertFalse((self.data / "sniper.db").exists())

    def test_malformed_journal_fails_without_echoing_private_content(self) -> None:
        journal = self.data / AggregateHistoryJournal.NAME
        journal.write_text('{"target_url":"PRIVATE_TARGET_SHOULD_NOT_APPEAR"}')
        journal.chmod(0o600)
        result = self.cli("--data-dir", str(self.data))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("Nuclei geçmişi güvenle okunamadı.", result.stderr)
        self.assertNotIn("PRIVATE_TARGET_SHOULD_NOT_APPEAR", result.stderr)
        self.assertNotIn(str(self.data), result.stderr)

    def test_world_readable_directory_and_symlink_are_rejected(self) -> None:
        self.data.chmod(0o755)
        readable = self.cli("--data-dir", str(self.data))
        self.assertEqual(readable.returncode, 1)
        self.data.chmod(0o700)
        link = self.root / "link"
        link.symlink_to(self.data, target_is_directory=True)
        linked = self.cli("--data-dir", str(link))
        self.assertEqual(linked.returncode, 1)

    def test_db_option_rejected_and_isolated_default_does_not_read_live(self) -> None:
        rejected = self.cli("--data-dir", str(self.data), "--db", str(self.data / "sniper.db"))
        self.assertEqual(rejected.returncode, 2)
        self.assertFalse((self.data / "sniper.db").exists())
        checkout = self.root / "isolated-app"
        checkout.mkdir()
        for name in ("cli_reports.py", "nuclei_aggregate_history.py"):
            shutil.copyfile(APP / name, checkout / name)
        isolated = self.cli(script=checkout / "cli_reports.py")
        self.assertEqual(isolated.returncode, 1)
        self.assertEqual(isolated.stdout, "")
        self.assertIn("Nuclei geçmişi güvenle okunamadı.", isolated.stderr)


if __name__ == "__main__":
    unittest.main()
