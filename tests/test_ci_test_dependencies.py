from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TEST_LOCK = ROOT / "requirements-test.lock"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
RUNNER = ROOT / "scripts" / "run_all_tests.py"

EXPECTED_TEST_DEPENDENCIES = {
    "iniconfig": "2.3.1",
    "pluggy": "1.6.0",
    "Pygments": "2.21.0",
    "pytest": "9.1.1",
}


def _load_runner():
    spec = importlib.util.spec_from_file_location("sniper_run_all_tests_contract", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        runtime_install = "python -m pip install --no-deps -r requirements-runtime.lock"
        test_install = "python -m pip install --no-deps -r requirements-test.lock"
        runtime_check = "python -m pip check"
        test_run = "python scripts/run_all_tests.py --verbose"

        self.assertIn(runtime_install, workflow)
        self.assertIn(test_install, workflow)
        self.assertIn(runtime_check, workflow)
        self.assertIn(test_run, workflow)
        self.assertLess(workflow.index(runtime_install), workflow.index(test_install))
        self.assertLess(workflow.index(test_install), workflow.index(runtime_check))
        self.assertLess(workflow.index(runtime_check), workflow.index(test_run))

    def test_tag_release_runs_the_same_dependency_and_full_test_gates(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        for fragment in (
            'node-version: "22.23.4"',
            "python -m pip install --no-deps -r requirements-runtime.lock",
            "python -m pip install --no-deps -r requirements-test.lock",
            "python -m pip check",
            "python scripts/run_all_tests.py --verbose",
        ):
            self.assertIn(fragment, workflow)

    def test_ci_and_release_boot_the_built_container_until_healthy(self) -> None:
        for path in (WORKFLOW, RELEASE_WORKFLOW):
            workflow = path.read_text(encoding="utf-8")
            for fragment in (
                "docker build --tag sniper-community:${{ github.sha }} .",
                "docker run --detach",
                "SNIPER_ALLOW_UNAUTHENTICATED_REMOTE=1",
                "State.Health.Status",
                '"$health_status" = "healthy"',
                "docker rm --force",
            ):
                self.assertIn(fragment, workflow, f"{path.name}: {fragment}")

    def test_local_pytest_probe_requires_runtime_dependencies_in_same_interpreter(self) -> None:
        runner = _load_runner()
        completed = SimpleNamespace(returncode=0)
        with mock.patch.dict(runner.os.environ, {"SNIPER_PYTEST_PYTHON": "/test/python"}), \
                mock.patch.object(runner.Path, "exists", return_value=True), \
                mock.patch.object(runner.subprocess, "run", return_value=completed) as run:
            self.assertEqual(runner._pytest_python(), "/test/python")

        probe = run.call_args.args[0]
        self.assertEqual(probe[:2], ["/test/python", "-c"])
        for module in ("pytest", "cryptography", "packaging", "yaml"):
            self.assertIn(module, probe[2])

    def test_node_24_summary_is_counted(self) -> None:
        runner = _load_runner()
        output = "\n".join(("ℹ tests 408", "ℹ pass 408", "ℹ fail 0"))
        self.assertEqual(runner._summarize_node(output), {"tests": "408", "pass": "408", "fail": "0"})

    def test_readme_installs_both_locks_before_full_local_tests(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "python3 -m pip install --no-deps -r requirements-runtime.lock -r requirements-test.lock",
            readme,
        )


if __name__ == "__main__":
    unittest.main()
