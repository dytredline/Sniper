"""Pipfile.lock (pipenv JSON) SBOM envanteri testleri — tamamen çevrimdışı.

Kaynak oracle durumları:
- pipfile-sbom-oracle-20261014T185135Z (main/edge/hidden vakaları),
- pipfile-sbom-supplemental-oracle-20261014T1919Z (sembolik bağ / boyut yarışı,
  özel index gözlemi, sürümsüz kayıtlar).
"""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dependency_security
from dependency_security import (
    MAX_REPORT_BYTES,
    DependencySecurityError,
    _read_regular_file_bytes,
    discover_components,
    discover_inventory,
    generate_cyclonedx_sbom,
)

PYPI_SOURCE = {"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True}


def lock(default=None, develop=None, sources=None):
    return json.dumps({
        "_meta": {
            "hash": {"sha256": "0" * 64},
            "pipfile-spec": 6,
            "requires": {"python_version": "3.11"},
            "sources": sources if sources is not None else [PYPI_SOURCE],
        },
        "default": default if default is not None else {},
        "develop": develop if develop is not None else {},
    }, sort_keys=True)


def summary(doc):
    return [
        (
            item["name"],
            item.get("version"),
            item["purl"],
            next(p["value"] for p in item["properties"] if p["name"] == "sniper:manifest"),
            item.get("scope"),
        )
        for item in doc["components"]
    ]


def skipped_values(doc):
    return [p["value"] for p in doc["metadata"].get("properties", []) if p["name"] == "sniper:skipped-dependency"]


class PipfileLockSbomTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        self.allowed = (self.base.resolve(),)
        self.lockfile = self.project / "Pipfile.lock"

    def tearDown(self):
        self.temp.cleanup()

    def write(self, content):
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.lockfile.write_bytes(content)

    def sbom(self):
        return generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)

    def assert_rejected(self):
        with self.assertRaises(DependencySecurityError):
            self.sbom()

    # --- ana akış ---------------------------------------------------------
    def test_default_section_pinned_component(self):
        self.write(lock({"requests": {"version": "==2.32.3", "hashes": ["sha256:" + "a" * 64], "index": "pypi"}}))
        doc = self.sbom()
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertEqual(summary(doc), [("requests", "2.32.3", "pkg:pypi/requests@2.32.3", "Pipfile.lock", None)])
        self.assertNotIn("properties", doc["metadata"])
        self.assertEqual(doc, self.sbom())

    def test_default_and_develop_sections_with_scope(self):
        self.write(lock({"requests": {"version": "==2.32.3"}}, {"pytest": {"version": "==8.3.2"}}))
        doc = self.sbom()
        self.assertEqual(summary(doc), [
            ("pytest", "8.3.2", "pkg:pypi/pytest@8.3.2", "Pipfile.lock", "optional"),
            ("requests", "2.32.3", "pkg:pypi/requests@2.32.3", "Pipfile.lock", None),
        ])
        pytest_item = doc["components"][0]
        self.assertIn({"name": "sniper:dependency-section", "value": "develop"}, pytest_item["properties"])

    def test_duplicate_in_default_and_develop_is_single_required_component(self):
        self.write(lock({"requests": {"version": "==2.32.3"}}, {"requests": {"version": "==2.32.3"}}))
        self.assertEqual(summary(self.sbom()), [("requests", "2.32.3", "pkg:pypi/requests@2.32.3", "Pipfile.lock", None)])

    def test_different_versions_in_sections_are_both_kept(self):
        self.write(lock({"urllib3": {"version": "==2.2.3"}}, {"urllib3": {"version": "==1.26.20"}}))
        self.assertEqual(summary(self.sbom()), [
            ("urllib3", "1.26.20", "pkg:pypi/urllib3@1.26.20", "Pipfile.lock", "optional"),
            ("urllib3", "2.2.3", "pkg:pypi/urllib3@2.2.3", "Pipfile.lock", None),
        ])

    def test_develop_scope_dropped_when_required_elsewhere(self):
        (self.project / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
        self.write(lock({}, {"requests": {"version": "==2.32.3"}}))
        items = self.sbom()["components"]
        self.assertEqual(len(items), 1)
        self.assertNotIn("scope", items[0])

    def test_pep503_name_normalization_in_purl(self):
        self.write(lock({
            "Zope.Interface": {"version": "==7.1.1"},
            "typing_extensions": {"version": "==4.12.2"},
            "Flask__SQLAlchemy": {"version": "==3.1.1"},
        }))
        purls = sorted(item["purl"] for item in self.sbom()["components"])
        self.assertEqual(purls, [
            "pkg:pypi/flask-sqlalchemy@3.1.1",
            "pkg:pypi/typing-extensions@4.12.2",
            "pkg:pypi/zope-interface@7.1.1",
        ])

    def test_discover_components_contract_unchanged(self):
        self.write(lock({"requests": {"version": "==2.32.3"}}))
        result = discover_components(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[1][0]["manifest"], "Pipfile.lock")
        self.assertEqual(result[1][0]["ecosystem"], "PyPI")

    def test_existing_controls_unaffected(self):
        (self.project / "requirements.txt").write_text("flask==3.1.0\n", encoding="utf-8")
        (self.project / "package-lock.json").write_text(json.dumps(
            {"packages": {"node_modules/lodash": {"name": "lodash", "version": "4.17.20"}}}), encoding="utf-8")
        doc = self.sbom()
        self.assertEqual([item["purl"] for item in doc["components"]], ["pkg:npm/lodash@4.17.20", "pkg:pypi/flask@3.1.0"])
        self.assertNotIn("properties", doc["metadata"])

    # --- atlanan (bileşen üretilmeyen) kayıtlar -------------------------------
    def test_unpinned_and_non_registry_entries_are_skipped_with_warning(self):
        self.write(lock({
            "a-missing": {"index": "pypi", "hashes": ["sha256:" + "a" * 64]},
            "b-empty-pin": {"version": "=="},
            "c-range": {"version": ">=1.0"},
            "d-star": {"version": "*"},
            "e-wildcard": {"version": "==1.*"},
            "f-arbitrary": {"version": "===1.0"},
            "g-bare": {"version": "1.0"},
            "h-git": {"git": "https://example.invalid/repo.git", "ref": "abc", "version": "==1.0"},
            "i-path": {"path": "./local", "version": "==1.0"},
            "j-editable": {"editable": True, "version": "==1.0"},
            "k-file": {"file": "https://example.invalid/x.whl"},
            "ok": {"version": "==1.0"},
        }, {"m-compound": {"version": ">=1,<2"}}))
        doc = self.sbom()
        self.assertEqual([item["name"] for item in doc["components"]], ["ok"])
        self.assertEqual(skipped_values(doc), [
            "Pipfile.lock|default|a-missing|version_missing",
            "Pipfile.lock|default|b-empty-pin|version_pin_empty",
            "Pipfile.lock|default|c-range|version_not_pinned",
            "Pipfile.lock|default|d-star|version_not_pinned",
            "Pipfile.lock|default|e-wildcard|version_not_pinned",
            "Pipfile.lock|default|f-arbitrary|version_not_pinned",
            "Pipfile.lock|default|g-bare|version_not_pinned",
            "Pipfile.lock|default|h-git|vcs_or_local_path",
            "Pipfile.lock|default|i-path|vcs_or_local_path",
            "Pipfile.lock|default|j-editable|vcs_or_local_path",
            "Pipfile.lock|default|k-file|vcs_or_local_path",
            "Pipfile.lock|develop|m-compound|version_not_pinned",
        ])
        self.assertIn({"name": "sniper:skipped-dependency-count", "value": "12"}, doc["metadata"]["properties"])
        # VCS adresi SBOM'a sızmamalı.
        self.assertNotIn("example.invalid", json.dumps(doc))
        _root, _components, skipped = discover_inventory(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(len(skipped), 12)

    def test_supplemental_registry_without_version_is_not_silent(self):
        # supplemental oracle: edge_registry_version_missing / operator_only.
        self.write(lock({"requests": {"index": "pypi", "hashes": ["sha256:" + "a" * 64]}, "six": {"version": "=="}}))
        doc = self.sbom()
        self.assertEqual(doc["components"], [])
        self.assertEqual(skipped_values(doc), [
            "Pipfile.lock|default|requests|version_missing",
            "Pipfile.lock|default|six|version_pin_empty",
        ])

    def test_skipped_entries_change_serial(self):
        self.write(lock({"ok": {"version": "==1.0"}}))
        clean = self.sbom()["serialNumber"]
        self.write(lock({"ok": {"version": "==1.0"}, "loose": {"version": "*"}}))
        self.assertNotEqual(clean, self.sbom()["serialNumber"])

    # --- şema hataları (oracle edge vakaları) -----------------------------------
    def test_schema_errors_are_rejected(self):
        cases = {
            "malformed_json": "{broken",
            "root_array": "[]",
            "default_array": lock([], {}),
            "develop_string": lock({}, "x"),
            "version_nonstring": lock({"requests": {"version": 42}}),
            "version_empty": lock({"requests": {"version": ""}}),
            "version_blank": lock({"requests": {"version": "   "}}),
            "entry_not_object": lock({"requests": "==2.32.3"}),
            "unsafe_name": lock({"../evil": {"version": "==1.0"}}),
            "name_with_space": lock({"bad name": {"version": "==1.0"}}),
            "duplicate_json_key": '{"default": {"a": {"version": "==1.0"}}, "default": {}}',
            "nan_constant": '{"default": {}, "x": NaN}',
            "meta_not_object": json.dumps({"_meta": [], "default": {}}),
            "sources_not_list": json.dumps({"_meta": {"sources": {}}, "default": {}}),
            "source_without_url": lock({}, sources=[{"name": "pypi"}]),
            "duplicate_source_name": lock({}, sources=[PYPI_SOURCE, PYPI_SOURCE]),
            "index_unknown": lock({"requests": {"version": "==2.32.3", "index": "ghost"}}),
            "index_nonstring": lock({"requests": {"version": "==2.32.3", "index": 1}}),
            "index_non_http": lock({"x": {"version": "==1.0", "index": "local"}},
                                   sources=[PYPI_SOURCE, {"name": "local", "url": "file:///srv/wheels"}]),
        }
        for label, content in cases.items():
            with self.subTest(label):
                self.write(content)
                self.assert_rejected()

    def test_invalid_utf8_rejected(self):
        self.write(b'{"default": {"\xff": {}}}')
        self.assert_rejected()

    # --- güvenli dosya açma ---------------------------------------------------
    def test_symlink_rejected(self):
        seed = self.project / "Pipfile.seed"
        seed.write_text(lock({"requests": {"version": "==2.32.3"}}), encoding="utf-8")
        self.lockfile.symlink_to(seed.name)
        self.assert_rejected()

    def test_oversize_rejected(self):
        self.write(b" " * (MAX_REPORT_BYTES + 1))
        self.assert_rejected()

    def test_directory_and_fifo_rejected_without_blocking(self):
        self.lockfile.mkdir()
        self.assert_rejected()
        self.lockfile.rmdir()
        os.mkfifo(self.lockfile)
        self.assert_rejected()

    def test_symlink_swap_at_open_is_rejected(self):
        # Ön kontrol ile açılış arasına sembolik bağ yerleştirme yarışı: O_NOFOLLOW reddeder.
        self.write(lock({"requests": {"version": "==2.32.3"}}))
        outside = self.base / "outside.json"
        outside.write_text(lock({"outside-widget": {"version": "==9.9.9"}}), encoding="utf-8")
        real_open = os.open
        target = self.lockfile

        def swapping_open(path, flags, *args, **kwargs):
            if Path(path) == target and not target.is_symlink():
                target.unlink()
                target.symlink_to(outside)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(dependency_security.os, "open", swapping_open):
            with self.assertRaises(DependencySecurityError) as ctx:
                self.sbom()
        self.assertIn("simge", str(ctx.exception))

    def test_growth_after_fstat_is_rejected(self):
        # fstat sonrası dosya büyürse sınırlı okuma (limit+1) yarışı yakalar.
        self.write(lock({"requests": {"version": "==2.32.3"}}))
        real_fstat = os.fstat
        target = self.lockfile
        target_inode = target.stat().st_ino
        grown = []

        def growing_fstat(fd):
            result = real_fstat(fd)
            if result.st_ino == target_inode and not grown:
                grown.append(True)
                with open(target, "ab") as handle:
                    handle.write(b" " * (MAX_REPORT_BYTES + 1))
            return result

        with patch.object(dependency_security.os, "fstat", growing_fstat):
            with self.assertRaises(DependencySecurityError) as ctx:
                self.sbom()
        self.assertIn("boyut", str(ctx.exception))

    def test_bounded_reader_limits(self):
        (self.project / "small.bin").write_bytes(b"x" * 10)
        self.assertEqual(_read_regular_file_bytes(self.project, "small.bin", limit=10), b"x" * 10)
        with self.assertRaises(DependencySecurityError):
            _read_regular_file_bytes(self.project, "small.bin", limit=9)
        self.assertIsNone(_read_regular_file_bytes(self.project, "missing.bin"))

    # --- özel index / PURL repository_url --------------------------------------
    def test_private_index_adds_sanitized_repository_url(self):
        private = {
            "name": "internal",
            "url": "https://deploy:s3cr3t-pass@Internal.Example.invalid:8443/simple/?token=abc123#frag",
            "verify_ssl": True,
        }
        self.write(lock({
            "local-widget": {"version": "==1.2.3", "index": "internal"},
            "requests": {"version": "==2.32.3", "index": "pypi"},
            "six": {"version": "==1.16.0"},
        }, sources=[PYPI_SOURCE, private]))
        doc = self.sbom()
        purls = {item["name"]: item["purl"] for item in doc["components"]}
        self.assertEqual(purls["local-widget"],
                         "pkg:pypi/local-widget@1.2.3?repository_url=https://internal.example.invalid:8443/simple")
        self.assertEqual(purls["requests"], "pkg:pypi/requests@2.32.3")
        self.assertEqual(purls["six"], "pkg:pypi/six@1.16.0")
        dumped = json.dumps(doc)
        for secret in ("deploy", "s3cr3t", "token", "abc123", "frag"):
            self.assertNotIn(secret, dumped)

    def test_supplemental_private_index_observation(self):
        self.write(lock({"local-widget": {"index": "internal", "version": "==1.2.3"}},
                        sources=[{"name": "internal", "url": "https://internal.example.invalid/simple", "verify_ssl": True}]))
        self.assertEqual([item["purl"] for item in self.sbom()["components"]],
                         ["pkg:pypi/local-widget@1.2.3?repository_url=https://internal.example.invalid/simple"])

    def test_default_pypi_alias_has_no_qualifier(self):
        self.write(lock({"requests": {"version": "==2.32.3", "index": "legacy"}},
                        sources=[{"name": "legacy", "url": "https://pypi.python.org/simple/", "verify_ssl": True}]))
        self.assertEqual(self.sbom()["components"][0]["purl"], "pkg:pypi/requests@2.32.3")

    def test_private_index_url_special_characters_are_percent_encoded(self):
        self.write(lock({"w": {"version": "==1.0", "index": "corp"}},
                        sources=[PYPI_SOURCE, {"name": "corp", "url": "https://repo.example.invalid/py pi/simple+x", "verify_ssl": True}]))
        self.assertEqual(self.sbom()["components"][0]["purl"],
                         "pkg:pypi/w@1.0?repository_url=https://repo.example.invalid/py%20pi/simple%2Bx")


if __name__ == "__main__":
    unittest.main()
