"""22. tur güvenlik öz denetimi regresyon testleri: SBOM XML DTD koruması, konteyner açılmış boyut bütçesi,
saklama silme yolu sınırı."""
from __future__ import annotations

import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import container_scan
import data_retention
import sbom_formats


class SbomXmlDtdTests(unittest.TestCase):
    def test_doctype_after_long_comment_is_rejected(self):
        # Eskiden yalnız ilk 200 KB taranıyordu: uzun yorumla öne itilen DOCTYPE fark edilmiyordu.
        evil = ("<!--" + "x" * 300_000 + "-->"
                '<!DOCTYPE bom [<!ENTITY a "aaaa">]><bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components>'
                "<component><name>&a;</name><version>1</version></component></components></bom>")
        with self.assertRaises(sbom_formats.SbomError):
            sbom_formats.parse_sbom_bytes(evil.encode())

    def test_parser_level_guard_rejects_entities(self):
        with self.assertRaises(sbom_formats.SbomError):
            sbom_formats._safe_xml_root('<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')

    def test_plain_cyclonedx_xml_still_parses(self):
        ok = ('<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components><component>'
              "<name>lodash</name><version>4.17.4</version><purl>pkg:npm/lodash@4.17.4</purl></component></components></bom>")
        parsed = sbom_formats.parse_sbom_bytes(ok.encode())
        self.assertEqual(parsed["components"][0]["purl"], "pkg:npm/lodash@4.17.4")


class ContainerDeclaredBytesTests(unittest.TestCase):
    def test_layer_over_declared_budget_is_rejected(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for i in range(3):
                data = b"0" * 4096
                info = tarfile.TarInfo(f"usr/share/doc/f{i}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        vfs = container_scan.VirtualFS()
        with mock.patch.object(container_scan, "MAX_DECLARED_BYTES", 8192), \
                tarfile.open(fileobj=buf, mode="r|") as layer:
            with self.assertRaises(container_scan.ContainerScanError):
                container_scan._apply_layer(vfs, layer)


class RetentionPathTests(unittest.TestCase):
    def test_unlink_refuses_sibling_with_common_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "data"
            sibling = Path(tmp) / "data-eski"
            base.mkdir()
            sibling.mkdir()
            victim = sibling / "sniper.db.bak-x"
            victim.write_text("x")
            self.assertFalse(data_retention._unlink_inside(base, "../data-eski/sniper.db.bak-x"))
            self.assertTrue(victim.exists())
            inside = base / "a.tmp"
            inside.write_text("x")
            self.assertTrue(data_retention._unlink_inside(base, "a.tmp"))
            self.assertFalse(inside.exists())


if __name__ == "__main__":
    unittest.main()
