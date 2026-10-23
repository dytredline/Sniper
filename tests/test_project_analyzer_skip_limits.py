"""project_analyzer sınırları: büyük/üretilmiş/UTF-8 olmayan dosyalar ve bütçe aşımı projeyi reddetmez;
dosyalar atlanır ve uyarı olarak raporlanır."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import project_analyzer
from project_analyzer import ProjectRejected, analyze_project

VULN = 'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n'


class SkipInsteadOfRejectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "proj"
        self.root.mkdir()
        self.addCleanup(self.tmp.cleanup)

    def analyze(self, **kwargs):
        return analyze_project(str(self.root), allowed_roots=(self.root.parent,), **kwargs)

    def test_large_generated_and_non_utf8_files_are_skipped(self):
        (self.root / "app.py").write_text(VULN)
        (self.root / "big.py").write_text("x = 1\n" * 200_000)  # > 1 MB
        (self.root / "jquery.min.js").write_text("var a=1;")
        (self.root / "app.bundle.js").write_text("var b=2;")
        (self.root / "latin.py").write_bytes("s = 'café'\n".encode("latin-1"))
        (self.root / "logo.png").write_bytes(b"\x89PNG" + b"\x00" * 10)
        result = self.analyze()
        self.assertEqual(result["file_count"], 1)
        self.assertEqual(result["skipped_files"]["large"], 1)
        self.assertEqual(result["skipped_files"]["generated"], 2)
        self.assertEqual(result["skipped_files"]["encoding"], 1)
        self.assertNotIn("png", " ".join(result["skipped_files"]))
        self.assertEqual(len(result["warnings"]), 3)
        self.assertTrue(any("1 MB" in warning for warning in result["warnings"]))
        self.assertTrue(any(f["file"] == "app.py" and f["category"] for f in result["findings"]))

    def test_budget_overflow_skips_largest_sources(self):
        (self.root / "requirements.txt").write_text("flask==3.0.0\n")
        (self.root / "app.py").write_text(VULN)
        (self.root / "medium.py").write_text("y = 2\n" * 3_000)
        (self.root / "huge.py").write_text("z = 3\n" * 100_000)
        budget = len(VULN) + len("flask==3.0.0\n") + len("y = 2\n" * 3_000) + 10
        with mock.patch.object(project_analyzer, "MAX_TOTAL_BYTES", budget):
            result = self.analyze()
        self.assertEqual(result["skipped_files"]["budget"], 1)
        self.assertEqual(result["file_count"], 3)
        self.assertIn("requirements.txt", result["manifests"])

    def test_requested_file_count_limit_still_rejects(self):
        (self.root / "a.py").write_text("a = 1\n")
        (self.root / "b.py").write_text("b = 1\n")
        (self.root / "c.py").write_text("c = 1\n")
        (self.root / "huge.min.js").write_text("x")  # atlanan dosya sayılmaz
        with self.assertRaises(ProjectRejected):
            self.analyze(max_files=2)
        self.assertEqual(self.analyze(max_files=3)["file_count"], 3)

    def test_clean_project_has_no_warnings(self):
        (self.root / "app.py").write_text("print('ok')\n")
        result = self.analyze()
        self.assertEqual(result["skipped_files"], {})
        self.assertEqual(result["warnings"], [])

    def test_only_skipped_files_still_explains(self):
        (self.root / "big.py").write_text("x = 1\n" * 200_000)
        with self.assertRaises(ProjectRejected) as caught:
            self.analyze()
        self.assertIn("analiz dışında bırakıldı", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
