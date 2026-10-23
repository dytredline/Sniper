from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEST_LOCK = ROOT / "requirements-test.lock"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

EXPECTED_TEST_DEPENDENCIES = {
    "iniconfig": "2.3.1",
    "pluggy": "1.6.0",
    "Pygments": "2.21.0",
    "pytest": "9.1.1",
}


class CiTestDependencyContractTests(unittest.TestCase):
    def test_test_dependency_lock_is_complete_and_exact(self) -> None:
        lines = [
            line.strip()
            for line in TEST_LOCK.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        observed: dict[str, str] = {}
        for line in lines:
            self.assertEqual(line.count("=="), 1, line)
            name, version = line.split("==", 1)
            self.assertNotIn(name.casefold(), {item.casefold() for item in observed}, line)
            observed[name] = version
        self.assertEqual(observed, EXPECTED_TEST_DEPENDENCIES)

    def test_ci_installs_runtime_and_test_locks_before_running_tests(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        runtime_install = "python -m pip install -r requirements-runtime.lock"
        test_install = "python -m pip install -r requirements-test.lock"
        test_run = "python scripts/run_all_tests.py --verbose"

        self.assertIn(runtime_install, workflow)
        self.assertIn(test_install, workflow)
        self.assertIn(test_run, workflow)
        self.assertLess(workflow.index(runtime_install), workflow.index(test_install))
        self.assertLess(workflow.index(test_install), workflow.index(test_run))


if __name__ == "__main__":
    unittest.main()
