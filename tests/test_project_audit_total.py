import tempfile
import unittest
from pathlib import Path

from storage import Store

class TestProjectAuditTotal(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for the SQLite DB
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "sniper.db"
        self.store = Store(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _dummy_result(self, idx: int) -> dict:
        return {
            "created_at": "2023-01-01T00:00:00Z",
            "project_path": f"/tmp/project{idx}",
            "project_name": f"project{idx}",
            "score": 50,
            "grade": "C",
            "file_count": 1,
            "bytes_scanned": 100,
            "findings": [],
        }

    def test_total_and_limited_listing(self):
        # Insert 31 audits
        for i in range(31):
            self.store.create_project_audit(self._dummy_result(i))

        # The list should be capped at 30 entries
        audits = self.store.list_project_audits()
        self.assertEqual(len(audits), 30, "list_project_audits should return at most 30 items")

        # The total count should reflect all 31 stored audits
        total = self.store.count_project_audits()
        self.assertEqual(total, 31, "count_project_audits should return the full number of stored audits")
