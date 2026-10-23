import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestSemgrepPickleRuleApi(unittest.TestCase):
    def setUp(self):
        self._temp_home = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_test_home_")
        self._home_dir = Path(self._temp_home.name)

    def tearDown(self):
        self._temp_home.cleanup()

    def test_semgrep_pickle_rule_api(self):
        binary = os.environ.get("SNIPER_TEST_SEMGREP_BINARY")
        rules = os.environ.get("SNIPER_TEST_SEMGREP_RULES")
        if not binary or not rules:
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY or SNIPER_TEST_SEMGREP_RULES not set")

        b = Path(binary)
        r = Path(rules)
        if not b.is_absolute() or not b.is_file() or b.is_symlink() or not os.access(str(b), os.X_OK):
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY not valid")
        if not r.is_absolute() or not r.is_file() or r.is_symlink():
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_RULES not valid")

        env_vars = {
            "SNIPER_SEMGREP_BINARY": str(b),
            "SNIPER_SEMGREP_RULES": str(r),
            "SNIPER_DATA_DIR": str(self._home_dir),
        }

        with patch.dict(os.environ, env_vars, clear=False):
            from semgrep_active import run_local_semgrep

            projects = {}
            for name, content in [
                ("eval", "eval(1 + 1)"),
                ("pickle.loads", "import pickle\npickle.loads(b'x')"),
                ("pickle.load", "import pickle\nwith open('f','rb') as f:\n    pickle.load(f)"),
                ("pickle.dumps", "import pickle\npickle.dumps(42)"),
                ("os.system", "import os\nos.system('echo hello')"),
                ("subprocess.run-shell-true", "import subprocess\nsubprocess.run('echo hello', shell=True)"),
                ("subprocess.Popen-shell-true", "import subprocess\nsubprocess.Popen('echo hello', shell=True)"),
                ("yaml.load-unsafe", "import yaml\nyaml.load('x: 1', Loader=yaml.Loader)"),
                ("yaml.safe_load", "import yaml\nyaml.safe_load('x: 1')"),
                ("subprocess.shell-false", "import subprocess\nsubprocess.run(['echo', 'hello'], shell=False)"),
            ]:
                proj = self._home_dir / name
                proj.mkdir(parents=True, exist_ok=True)
                (proj / "main.py").write_text(content, encoding="utf-8")
                projects[name] = str(proj)

            expected_counts = {
                "eval": 1,
                "pickle.loads": 1,
                "pickle.load": 1,
                "pickle.dumps": 0,
                "os.system": 1,
                "subprocess.run-shell-true": 1,
                "subprocess.Popen-shell-true": 1,
                "yaml.load-unsafe": 1,
                "yaml.safe_load": 0,
                "subprocess.shell-false": 0,
            }

            for name, proj_path in projects.items():
                summary = run_local_semgrep(proj_path)

                self.assertIn("result_count", summary)
                self.assertIn("severity_counts", summary)
                self.assertIn("report_sha256", summary)
                self.assertIn("profile", summary)

                self.assertEqual(summary["profile"], "local-trusted-rules-v1")

                self.assertEqual(
                    summary["result_count"],
                    expected_counts[name],
                    f"{name}: expected result_count={expected_counts[name]}, got {summary['result_count']}"
                )

    def test_semgrep_new_rules_positive_cases(self):
        binary = os.environ.get("SNIPER_TEST_SEMGREP_BINARY")
        rules = os.environ.get("SNIPER_TEST_SEMGREP_RULES")
        if not binary or not rules:
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY or SNIPER_TEST_SEMGREP_RULES not set")

        b = Path(binary)
        r = Path(rules)
        if not b.is_absolute() or not b.is_file() or b.is_symlink() or not os.access(str(b), os.X_OK):
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY not valid")
        if not r.is_absolute() or not r.is_file() or r.is_symlink():
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_RULES not valid")

        env_vars = {
            "SNIPER_SEMGREP_BINARY": str(b),
            "SNIPER_SEMGREP_RULES": str(r),
            "SNIPER_DATA_DIR": str(self._home_dir),
        }

        with patch.dict(os.environ, env_vars, clear=False):
            from semgrep_active import run_local_semgrep

            projects = {}
            for name, content in [
                ("os.system", "import os\nos.system('ls')"),
                ("subprocess.run-shell-true", "import subprocess\nsubprocess.run('ls', shell=True)"),
                ("yaml.load-unsafe", "import yaml\nyaml.load('x', Loader=yaml.Loader)"),
            ]:
                proj = self._home_dir / name
                proj.mkdir(parents=True, exist_ok=True)
                (proj / "main.py").write_text(content, encoding="utf-8")
                projects[name] = str(proj)

            for name, proj_path in projects.items():
                summary = run_local_semgrep(proj_path)
                self.assertGreater(summary["result_count"], 0, f"{name}: expected at least one finding")

    def test_semgrep_safe_patterns_zero_findings(self):
        binary = os.environ.get("SNIPER_TEST_SEMGREP_BINARY")
        rules = os.environ.get("SNIPER_TEST_SEMGREP_RULES")
        if not binary or not rules:
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY or SNIPER_TEST_SEMGREP_RULES not set")

        b = Path(binary)
        r = Path(rules)
        if not b.is_absolute() or not b.is_file() or b.is_symlink() or not os.access(str(b), os.X_OK):
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_BINARY not valid")
        if not r.is_absolute() or not r.is_file() or r.is_symlink():
            raise unittest.SkipTest("SNIPER_TEST_SEMGREP_RULES not valid")

        env_vars = {
            "SNIPER_SEMGREP_BINARY": str(b),
            "SNIPER_SEMGREP_RULES": str(r),
            "SNIPER_DATA_DIR": str(self._home_dir),
        }

        with patch.dict(os.environ, env_vars, clear=False):
            from semgrep_active import run_local_semgrep

            projects = {}
            for name, content in [
                ("subprocess.shell-false", "import subprocess\nsubprocess.run(['ls'], shell=False)"),
                ("yaml.safe_load", "import yaml\nyaml.safe_load('x: 1')"),
            ]:
                proj = self._home_dir / name
                proj.mkdir(parents=True, exist_ok=True)
                (proj / "main.py").write_text(content, encoding="utf-8")
                projects[name] = str(proj)

            for name, proj_path in projects.items():
                summary = run_local_semgrep(proj_path)
                self.assertEqual(summary["result_count"], 0, f"{name}: expected zero findings")


if __name__ == "__main__":
    unittest.main()