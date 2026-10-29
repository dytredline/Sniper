from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
from pathlib import Path

import pytest

from scripts.install_nuclei_catalog import CatalogInstallError, install_catalog


def _archive(path: Path, *, duplicate_id: bool = False, symlink: bool = False) -> str:
    files = {
        "nuclei-templates-10.5.0/http/cves/demo.yaml": b"id: demo-template\ninfo:\n  name: Demo\n",
        "nuclei-templates-10.5.0/http/misc/second.yml": (
            b"id: demo-template\ninfo:\n  name: Duplicate\n" if duplicate_id
            else b"id: second-template\ninfo:\n  name: Second\n"
        ),
        "nuclei-templates-10.5.0/http/technologies/wappalyzer-mapping.yml": b"demo: [header]\n",
        "nuclei-templates-10.5.0/README.md": b"ignored\n",
    }
    with tarfile.open(path, "w:gz") as bundle:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.size = len(raw)
            bundle.addfile(info, io.BytesIO(raw))
        if symlink:
            info = tarfile.TarInfo("nuclei-templates-10.5.0/http/misc/escape.yaml")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            bundle.addfile(info)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_official_archive_builds_deterministic_read_only_http_catalog(tmp_path: Path) -> None:
    archive = tmp_path / "catalog.tar.gz"
    digest = _archive(archive)
    result = install_catalog(
        archive, tmp_path / "catalog", expected_archive_sha256=digest, expected_template_count=2)

    root = tmp_path / "catalog"
    pin = root / "SNIPER-HTTP-CATALOG-PIN-v2.json"
    index = root / "SNIPER-HTTP-ID-INDEX.json"
    pin_doc = json.loads(pin.read_text(encoding="utf-8"))
    index_doc = json.loads(index.read_text(encoding="utf-8"))
    assert result == {
        "format": "sniper-nuclei-http-catalog-install-v1",
        "version": "v10.5.0",
        "template_count": 2,
        "archive_sha256": digest,
        "pin_sha256": hashlib.sha256(pin.read_bytes()).hexdigest(),
        "index_sha256": hashlib.sha256(index.read_bytes()).hexdigest(),
        "mapping_sha256": hashlib.sha256(b"demo: [header]\n").hexdigest(),
    }
    assert [row[0] for row in index_doc["ids_paths_hashes"]] == ["demo-template", "second-template"]
    assert all("wappalyzer-mapping" not in row[0] for row in pin_doc["paths_and_hashes"])
    assert not (root / "README.md").exists()
    assert stat.S_IMODE(pin.stat().st_mode) == 0o444
    assert stat.S_IMODE((root / "http").stat().st_mode) == 0o555


def test_catalog_install_rejects_wrong_digest_duplicate_ids_and_symlinks(tmp_path: Path) -> None:
    archive = tmp_path / "catalog.tar.gz"
    digest = _archive(archive)
    with pytest.raises(CatalogInstallError, match="SHA-256"):
        install_catalog(
            archive, tmp_path / "wrong", expected_archive_sha256="0" * 64,
            expected_template_count=2)

    duplicate = tmp_path / "duplicate.tar.gz"
    duplicate_digest = _archive(duplicate, duplicate_id=True)
    with pytest.raises(CatalogInstallError, match="template ID"):
        install_catalog(
            duplicate, tmp_path / "duplicate", expected_archive_sha256=duplicate_digest,
            expected_template_count=2)

    linked = tmp_path / "linked.tar.gz"
    linked_digest = _archive(linked, symlink=True)
    with pytest.raises(CatalogInstallError, match="regular file"):
        install_catalog(
            linked, tmp_path / "linked", expected_archive_sha256=linked_digest,
            expected_template_count=2)


def test_existing_destination_is_never_replaced(tmp_path: Path) -> None:
    archive = tmp_path / "catalog.tar.gz"
    digest = _archive(archive)
    destination = tmp_path / "catalog"
    destination.mkdir()
    with pytest.raises(CatalogInstallError, match="already exists"):
        install_catalog(
            archive, destination, expected_archive_sha256=digest, expected_template_count=2)
