"""Portable checks for the macOS Docker deployment and project-copy helpers."""

from __future__ import annotations

from pathlib import Path
import runpy
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = runpy.run_path(str(ROOT / "scripts/deploy-community-tools"))
IMPORT = runpy.run_path(str(ROOT / "scripts/import-community-project"))


class DockerDeploymentTests(unittest.TestCase):
    def test_all_five_ready_profiles_are_required(self) -> None:
        routes = DEPLOY["REQUIRED_PROFILES"]
        ready = {"tools": [
            {"id": engine, "profiles": [{"route": route, "runtime": "precheck_passed"}]}
            for engine, route in routes.items()
        ]}
        self.assertEqual(DEPLOY["missing_engines"](ready), [])
        ready["tools"][0]["profiles"][0]["runtime"] = "unavailable"
        self.assertEqual(DEPLOY["missing_engines"](ready), ["nuclei"])
        ready["tools"][-1]["profiles"][0]["runtime"] = "unavailable"
        self.assertEqual(DEPLOY["missing_engines"](ready), ["nuclei", "opengrep"])

    def test_missing_readiness_never_reports_installed(self) -> None:
        self.assertEqual(len(DEPLOY["missing_engines"]({})), 5)


class DockerProjectImportTests(unittest.TestCase):
    def test_rejects_broad_and_symlinked_roots(self) -> None:
        validate = IMPORT["validate_source"]
        with self.assertRaises(ValueError):
            validate(str(Path.home()))
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / "project"
            real.mkdir()
            link = Path(temp) / "shortcut"
            link.symlink_to(real, target_is_directory=True)
            self.assertEqual(validate(str(real)), real.resolve())
            with self.assertRaises(ValueError):
                validate(str(link))

    def test_project_name_is_a_single_safe_path_segment(self) -> None:
        validate = IMPORT["validate_name"]
        self.assertEqual(validate("my-project_1"), "my-project_1")
        for invalid in ("", ".", "..", "../other", "two words", "-option", "a" * 65):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate(invalid)


if __name__ == "__main__":
    unittest.main()
