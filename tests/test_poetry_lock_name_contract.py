'''Test Poetry lock file name sözleşmesi - dağıtım adı doğrulama.'''
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dependency_security import (
    DependencySecurityError,
    discover_components,
    _poetry_components,
)


class TestPoetryLockNameContract(unittest.TestCase):
    """Poetry lock file name alanı için dağıtım adı sözleşmesi testleri."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.allowed = (self.base, Path("/mnt").resolve())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_poetry_lock(self, content: str, path: Path | None = None) -> Path:
        lock = path or self.project / "poetry.lock"
        lock.write_text(content, encoding="utf-8")
        return lock

    def test_name_bad_question_mark_rejected(self):
        """name = 'bad?name' soru işareti içeriyorsa DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = "bad?name"\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_bad_hash_rejected(self):
        """name = 'bad#name' diyez işareti içeriyorsa DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = "bad#name"\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_bad_at_sign_rejected(self):
        """name = 'bad@name' at işareti içeriyorsa DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = "bad@name"\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_bad_colon_rejected(self):
        """name = 'bad:name' iki nokta işareti içeriyorsa DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = "bad:name"\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_with_space_rejected(self):
        """name = 'bad name' boşluk içeriyorsa DependencySecurityError vermelidir."""
        self.write_poetry_lock('[[package]]\nname = "bad name"\nversion = "1.0"\n')
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_single_quotes_in_toml_rejected(self):
        """TOML içinde tek tırnaklarla yazılmış kötü isim reddedilir."""
        # TOML'de stringler çift tırnakla olmalı, tek tırnak hatası yaratabilir
        self.write_poetry_lock("[[package]]\nname = 'bad name'\nversion = '1.0'\n")
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())

    def test_name_requests_accepted(self):
        """requests: geçerli bir dağıtım adı kabul edilir."""
        self.write_poetry_lock('[[package]]\nname = "requests"\nversion = "2.31.0"\n')
        components = _poetry_components(self.project)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "requests")

    def test_name_zope_interface_accepted(self):
        """zope.interface: geçerli bir dağıtım adı kabul edilir."""
        self.write_poetry_lock('[[package]]\nname = "zope.interface"\nversion = "5.5.2"\n')
        components = _poetry_components(self.project)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "zope.interface")

    def test_name_my_package_accepted(self):
        """my_package: geçerli bir dağıtım adı kabul edilir."""
        self.write_poetry_lock('[[package]]\nname = "my_package"\nversion = "1.0.0"\n')
        components = _poetry_components(self.project)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "my_package")

    def test_name_some_package_accepted(self):
        """some-package: geçerli bir dağıtım adı kabul edilir."""
        self.write_poetry_lock('[[package]]\nname = "some-package"\nversion = "0.1.0"\n')
        components = _poetry_components(self.project)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "some-package")

    def test_name_with_numbers_accepted(self):
        """3dengine: sayılar içeren geçerli bir dağıtım adı kabul edilir."""
        self.write_poetry_lock('[[package]]\nname = "3dengine"\nversion = "2.0.1"\n')
        components = _poetry_components(self.project)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "3dengine")

    def test_name_multiple_packages_mixed_valid_invalid(self):
        """Birden fazla paket: biri geçersiz ise tüm işlem başarısız olmalı."""
        content = '''[[package]]
name = "valid-package"
version = "1.0.0"

[[package]]
name = "bad?invalid"
version = "2.0.0"

[[package]]
name = "another-valid"
version = "3.0.0"
'''
        self.write_poetry_lock(content)
        with self.assertRaises(DependencySecurityError) as cm:
            discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertIn("name", str(cm.exception).lower())
