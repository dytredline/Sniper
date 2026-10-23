"""Unit tests for Poetry lockfile SBOM support."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dependency_security import (
    DependencySecurityError,
    discover_components,
    generate_cyclonedx_sbom,
)


class PoetryLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.allowed = (self.base, Path("/mnt").resolve())

    def tearDown(self):
        self.temp.cleanup()

    def _write_poetry_lock(self, content: str, path: Path | None = None) -> Path:
        lock = path or self.project / "poetry.lock"
        lock.write_text(content, encoding="utf-8")
        return lock

    def test_poetry_lock_basic_extraction(self):
        """Valid poetry.lock extracts components with PyPI ecosystem."""
        self._write_poetry_lock(
            '[[package]]\nname = "requests"\nversion = "2.32.5"\ngroups = ["main"]\n'
            '\n[[package]]\nname = "urllib3"\nversion = "2.5.0"\ngroups = ["main"]\n'
            '\n[metadata]\nlock-version = "2.1"\n'
        )
        _, components = discover_components(str(self.project), allowed_roots=self.allowed)
        names = {c["name"] for c in components}
        self.assertEqual(names, {"requests", "urllib3"})
        for c in components:
            self.assertEqual(c["ecosystem"], "PyPI")
            self.assertEqual(c["manifest"], "poetry.lock")

    def test_poetry_lock_purl_generation(self):
        """CycloneDX SBOM generates correct purls for poetry.lock."""
        self._write_poetry_lock(
            '[[package]]\nname = "django"\nversion = "5.0.8"\n'
        )
        sbom = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        purls = {item["purl"] for item in sbom["components"]}
        self.assertEqual(purls, {"pkg:pypi/django@5.0.8"})
        django = next(item for item in sbom["components"] if item["name"] == "django")
        self.assertEqual(django["version"], "5.0.8")

    def test_poetry_lock_deduplication_with_pyproject(self):
        """Deduplication between poetry.lock and pyproject.toml works."""
        self._write_poetry_lock(
            '[[package]]\nname = "requests"\nversion = "2.32.5"\n'
        )
        (self.project / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests==2.32.5"]\n', encoding="utf-8"
        )
        _, components = discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "requests")

    def test_poetry_lock_symlink_rejected(self):
        """poetry.lock symlinks are rejected."""
        lock = self.project / "poetry.lock"
        lock.symlink_to(self.base / "external.lock")
        with self.assertRaisesRegex(DependencySecurityError, "simge bağlantısı"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_oversized_rejected(self):
        """poetry.lock >8MB is rejected."""
        lock = self.project / "poetry.lock"
        lock.write_bytes(b"x" * 8_000_001)
        with self.assertRaisesRegex(DependencySecurityError, "boyut"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_malformed_toml_rejected(self):
        """Invalid TOML in poetry.lock is rejected."""
        self._write_poetry_lock("[[package]\n")
        with self.assertRaisesRegex(DependencySecurityError, "geçerli TOML"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_invalid_package_list_schema(self):
        """package = 42 is rejected."""
        self._write_poetry_lock("package = 42\n")
        with self.assertRaisesRegex(DependencySecurityError, "şema"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_invalid_package_array_schema(self):
        """package = [42] is rejected."""
        self._write_poetry_lock("package = [42]\n")
        with self.assertRaisesRegex(DependencySecurityError, "şema"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_missing_name(self):
        """[[package]] without name is rejected."""
        self._write_poetry_lock('[[package]]\nversion = "1.0"\n')
        with self.assertRaisesRegex(DependencySecurityError, "name"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_missing_version(self):
        """[[package]] without version is rejected."""
        self._write_poetry_lock('[[package]]\nname = "demo"\n')
        with self.assertRaisesRegex(DependencySecurityError, "version"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_empty_name(self):
        """[[package]] with name = "" is rejected."""
        self._write_poetry_lock('[[package]]\nname = ""\nversion = "1.0"\n')
        with self.assertRaisesRegex(DependencySecurityError, "name"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_numeric_version(self):
        """[[package]] with numeric version is rejected."""
        self._write_poetry_lock('[[package]]\nname = "demo"\nversion = 1\n')
        with self.assertRaisesRegex(DependencySecurityError, "version"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_invalid_item_type(self):
        """[[package]] with non-dict item is rejected."""
        self._write_poetry_lock('[package]\n')
        with self.assertRaisesRegex(DependencySecurityError, "şema"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_empty_component_list(self):
        """Valid poetry.lock with no packages returns empty components."""
        self._write_poetry_lock(
            '\n[metadata]\nlock-version = "2.1"\n'
        )
        _, components = discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(components, [])

    def test_poetry_lock_max_components_limit(self):
        """MAX_COMPONENTS limit is enforced."""
        lines = []
        for i in range(20001):
            lines.append(f'[[package]]\nname = "pkg{i}"\nversion = "1.0"\n\n')
        self._write_poetry_lock("".join(lines))
        with self.assertRaisesRegex(DependencySecurityError, "sınırı aşıyor"):
            discover_components(str(self.project), allowed_roots=self.allowed)

    def test_poetry_lock_manifest_field(self):
        """SBOM components include correct manifest field."""
        self._write_poetry_lock(
            '[[package]]\nname = "test-pkg"\nversion = "2.0"\n'
        )
        sbom = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        test_pkg = next(item for item in sbom["components"] if item["name"] == "test-pkg")
        props = test_pkg.get("properties", [])
        manifest_prop = next((p for p in props if p["name"] == "sniper:manifest"), None)
        self.assertEqual(manifest_prop["value"], "poetry.lock")


if __name__ == "__main__":
    unittest.main()
