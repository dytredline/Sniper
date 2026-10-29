"""Terraform provider lock inventory and CycloneDX behavior."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dependency_security import (
    DependencySecurityError,
    discover_components,
    generate_cyclonedx_sbom,
)
import project_analyzer
import osv_offline


LOCK = '''
# This file is maintained automatically by "terraform init".
provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.92.0"
  constraints = ">= 5.0.0, < 6.0.0"
  hashes = [
    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "zh:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  ]
}

provider "registry.terraform.io/hashicorp/random" {
  version = "3.7.2"
  hashes = ["h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="]
}
'''


class TerraformProviderLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.allowed = (self.base,)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_lock(self, content: str = LOCK, directory: Path | None = None) -> Path:
        root = directory or self.project
        root.mkdir(parents=True, exist_ok=True)
        path = root / ".terraform.lock.hcl"
        path.write_text(content, encoding="utf-8")
        return path

    def test_provider_versions_enter_inventory_and_cyclonedx_deterministically(self) -> None:
        self.write_lock()

        _, components = discover_components(str(self.project), allowed_roots=self.allowed)

        self.assertEqual(
            components,
            [
                {
                    "name": "registry.terraform.io/hashicorp/aws",
                    "version": "5.92.0",
                    "ecosystem": "Terraform",
                    "manifest": ".terraform.lock.hcl",
                },
                {
                    "name": "registry.terraform.io/hashicorp/random",
                    "version": "3.7.2",
                    "ecosystem": "Terraform",
                    "manifest": ".terraform.lock.hcl",
                },
            ],
        )
        first = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        second = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(first, second)
        self.assertEqual(
            {item["purl"] for item in first["components"]},
            {
                "pkg:generic/registry.terraform.io/hashicorp/aws@5.92.0",
                "pkg:generic/registry.terraform.io/hashicorp/random@3.7.2",
            },
        )
        offline = osv_offline.match_components(components)
        self.assertEqual(offline["skipped"]["unsupported_ecosystem"], 2)
        self.assertEqual(offline["document"]["results"][0]["packages"], [])

    def test_nested_lock_is_discovered_and_manifest_path_is_preserved(self) -> None:
        self.write_lock(directory=self.project / "infra")

        _, components = discover_components(str(self.project), allowed_roots=self.allowed)

        self.assertEqual(len(components), 2)
        self.assertEqual({item["manifest"] for item in components}, {"infra/.terraform.lock.hcl"})

    def test_missing_exact_version_is_rejected_instead_of_using_constraint(self) -> None:
        self.write_lock(
            'provider "registry.terraform.io/hashicorp/aws" {\n'
            '  constraints = ">= 5.0.0"\n'
            '}\n'
        )

        with self.assertRaisesRegex(DependencySecurityError, "version"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_unclosed_hash_list_is_rejected(self) -> None:
        self.write_lock(
            'provider "registry.terraform.io/hashicorp/aws" {\n'
            '  version = "5.92.0"\n'
            '  hashes = [\n'
            '    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="\n'
            '}\n'
        )

        with self.assertRaisesRegex(DependencySecurityError, "listesi kapanmamış"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_project_analyzer_classifies_lock_as_manifest(self) -> None:
        self.write_lock()

        result = project_analyzer.analyze_project(str(self.project), allowed_roots=self.allowed)

        self.assertIn(".terraform.lock.hcl", result["manifests"])


if __name__ == "__main__":
    unittest.main()

