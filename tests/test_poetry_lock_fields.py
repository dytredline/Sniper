'''Test Poetry lockfield name alanı güvenliğini.'''
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dependency_security import (
    DependencySecurityError,
    discover_components,
)


class TestPoetryLockFieldSecurity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.allowed = (self.base, Path("/mnt").resolve())

    def tearDown(self):
        self.temp.cleanup()

    def write_poetry_lock(self, content: str, path: Path | None = None) -> Path:
        lock = path or self.project / "poetry.lock"
        lock.write_text(content, encoding="utf-8")
        return lock

    def test_name_numeric_rejected(self):
        """name = 123 sayısal ise DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = 123\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_table_rejected(self):
        """name = {path=\"bad\"} tablo nesnesi ise DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = {path = "bad"}\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_path_traversal_rejected(self):
        """name = "../bad/name" yol ayracı içeriyorsa DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = "../bad/name"\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_invalid_utf8_rejected(self):
        """geçersiz UTF-8 içerikli poetry.lock DependencySecurityError vermelidir."""
        lock = self.project / "poetry.lock"
        # Geçersiz UTF-8 byte dizisi
        lock.write_bytes(b'[[package]]\nname = "\xff\xfe"\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError):
            discover_components(str(self.project), allowed_roots=self.allowed)
