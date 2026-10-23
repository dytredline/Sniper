from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build-community-source.py"
VALIDATOR = ROOT / ".github" / "scripts" / "validate-community-release.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommunityLicenseContractTests(unittest.TestCase):
    def test_public_docs_make_an_unambiguous_apache_2_grant(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

        self.assertIn("licensed under the Apache License 2.0", readme)
        self.assertIn("Apache-2.0 inbound=outbound", contributing)
        for text in (readme, contributing):
            self.assertNotIn("proposed license", text.casefold())
            self.assertNotIn("license choice is a release candidate", text.casefold())

    def test_release_validator_rejects_license_grant_regression(self) -> None:
        builder = _load(BUILDER, "community_license_builder_test")
        validator = _load(VALIDATOR, "community_license_validator_test")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "community"
            builder.build(ROOT, output)
            self.assertEqual(validator.validate(output, scan_release_tree=True), [])

            readme = output / "README.md"
            original = readme.read_text(encoding="utf-8")
            readme.write_text(
                original.replace(
                    "licensed under the Apache License 2.0",
                    "uses a proposed license",
                    1,
                ),
                encoding="utf-8",
            )
            failures = validator.validate(output, scan_release_tree=True)
            self.assertTrue(any("README.md" in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
