import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestSemgrepPickleRuleApi(unittest.TestCase):
    def setUp(self):
        # Ensure we use a clean temp dir under home for each test run
        self._temp_home = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_test_home_")
        self._home_dir = Path(self._temp_home.name)

    def tearDown(self):
        # Cleanup is automatic via TemporaryDirectory context, but ensure no leaks
        self._temp_home.cleanup()

    def test_semgrep_pickle_rule_api(self):
        # Skip if required env vars are missing
        binary = os.environ.get("SNIPER_TEST_SEMGREP_BINARY")
        rules = os.environ.get("SNIPER_TEST_SEMGREP_RULES")
        if not binary or not rules:
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY or SNIPER_TEST_SEMGREP_RULES not set")

        # Validate binary and rules
        b = Path(binary)
        r = Path(rules)
        if not b.is_absolute() or not b.is_file() or b.is_symlink() or not os.access(str(b), os.X_OK):
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY not valid")
        if not r.is_absolute() or not r.is_file() or r.is_symlink():
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_RULES not valid")

        # Set up environment via patch.dict (only for required vars)
        env_vars = {
            "SNIPER_SEMGREP_BINARY": str(b),
            "SNIPER_SEMGREP_RULES": str(r),
            "SNIPER_DATA_DIR": str(self._home_dir),
        }

        with patch.dict(os.environ, env_vars, clear=False):
            # Import runner inside context to avoid import-time side effects
            from semgrep_active import run_local_semgrep

            # Create synthetic project directories
            projects = {}
            for name, content in [
                ("eval", "eval(1 + 1)"),
                ("pickle.loads", "import pickle\npickle.loads(b'x')"),
                ("pickle.load", "import pickle\nwith open('f','rb') as f:\n    pickle.load(f)"),
                ("pickle.dumps", "import pickle\npickle.dumps(42)"),
            ]:
                proj = self._home_dir / name
                proj.mkdir(parents=True, exist_ok=True)
                (proj / "main.py").write_text(content, encoding="utf-8")
                projects[name] = str(proj)

            # Expected result counts per project
            expected_counts = {
                "eval": 1,
                "pickle.loads": 1,
                "pickle.load": 1,
                "pickle.dumps": 0,
            }

            for name, proj_path in projects.items():
                summary = run_local_semgrep(proj_path)

                # Assert required aggregate keys exist and have correct types
                self.assertIn("result_count", summary)
                self.assertIn("severity_counts", summary)
                self.assertIn("report_sha256", summary)
                self.assertIn("profile", summary)

                # Assert expected profile
                self.assertEqual(summary["profile"], "local-trusted-rules-v1")

                # Assert expected result_count
                self.assertEqual(
                    summary["result_count"],
                    expected_counts[name],
                    f"{name}: expected result_count={expected_counts[name]}, got {summary['result_count']}"
                )

                # Do NOT assert 'results' key exists (aggregate-only format)
                # Do NOT assert raw results list


if __name__ == "__main__":
    unittest.main()
