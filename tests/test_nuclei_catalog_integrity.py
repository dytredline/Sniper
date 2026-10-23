from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from nuclei_catalog_integrity import verify_http_catalog


def _make_fake_yaml(filename: str, content: str) -> tuple[Path, str]:
    p = Path(filename)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return p, sha


def _make_test_catalog(tmp: Path) -> tuple[Path, Path, int, dict]:
    """Create a minimal two-YAML test catalog plus a separate mapping.yml."""
    http_dir = tmp / "http"
    tech_dir = http_dir / "technologies"
    http_dir.mkdir(parents=True)
    tech_dir.mkdir(parents=True)

    # Create two YAML files counted in pin
    t1_path, t1_sha = _make_fake_yaml(http_dir / "test1.yaml", "id: test1")
    t2_path, t2_sha = _make_fake_yaml(http_dir / "test2.yaml", "id: test2")

    # Create mapping.yml (NOT counted in the two rows)
    mapping_path, mapping_sha = _make_fake_yaml(tech_dir / "wappalyzer-mapping.yml", "mapping: []")

    # Pin index with expected structure (only two rows for templates)
    paths_and_hashes = [
        ["http/test1.yaml", t1_sha],
        ["http/test2.yaml", t2_sha],
    ]

    # Construct pin_data without self-reference; sha256 field is a placeholder
    pin_data_body = {
        "version": "v10.5.0",
        "count": 2,
        "paths_and_hashes": paths_and_hashes,
        "scope": "http-templates",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    }

    pin_json = json.dumps(pin_data_body, separators=(',', ':'))
    pin_sha = hashlib.sha256(pin_json.encode("utf-8")).hexdigest()

    pin_path = tmp / "SNIPER-HTTP-ID-INDEX.json"
    pin_path.write_text(pin_json)

    return tmp, pin_path, 2, {"t1": t1_sha, "t2": t2_sha, "mapping": mapping_sha, "pin": pin_sha}


def test_passing_two_template_catalog():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root, pin_path, count, hashes = _make_test_catalog(tmp)

        result = verify_http_catalog(
            root=root,
            pin_path=pin_path,
            expected_pin_sha256=hashes["pin"],
            expected_count=2,
            mapping_sha256=hashes["mapping"],
        )

        assert result["status"] == "ok"
        assert result["template_count"] == 2
        assert result["pin_sha256"] == hashes["pin"].lower()


def test_modified_template_fails():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root, pin_path, count, hashes = _make_test_catalog(tmp)

        # Modify one file *after* pin creation
        (root / "http" / "test1.yaml").write_text("id: modified")

        with pytest.raises(ValueError, match="SHA256 uyuşmuyor"):
            verify_http_catalog(
                root=root,
                pin_path=pin_path,
                expected_pin_sha256=hashes["pin"],
                expected_count=2,
                mapping_sha256=hashes["mapping"],
            )


def test_unexpected_yaml_fails():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root, pin_path, count, hashes = _make_test_catalog(tmp)

        # Add unexpected YAML
        _make_fake_yaml(root / "http" / "extra.yaml", "id: extra")

        with pytest.raises(ValueError, match="Dosya kümesi uyuşmuyor"):
            verify_http_catalog(
                root=root,
                pin_path=pin_path,
                expected_pin_sha256=hashes["pin"],
                expected_count=2,
                mapping_sha256=hashes["mapping"],
            )


def test_symlink_in_catalog_fails():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root, pin_path, count, hashes = _make_test_catalog(tmp)

        # Create symlink inside http/
        link_path = root / "http" / "link.yaml"
        link_path.symlink_to(root / "http" / "test1.yaml")

        with pytest.raises(ValueError, match="sembolik bağlı dosya bulundu"):
            verify_http_catalog(
                root=root,
                pin_path=pin_path,
                expected_pin_sha256=hashes["pin"],
                expected_count=2,
                mapping_sha256=hashes["mapping"],
            )


def test_wrong_pin_sha256_fails():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root, pin_path, count, hashes = _make_test_catalog(tmp)

        with pytest.raises(ValueError, match="Sabitleme SHA256 değeri uyuşmuyor"):
            verify_http_catalog(
                root=root,
                pin_path=pin_path,
                expected_pin_sha256="0000000000000000000000000000000000000000000000000000000000000000",
                expected_count=2,
                mapping_sha256=hashes["mapping"],
            )


def test_relative_root_fails():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root = Path("relative-catalog")  # explicitly relative
        pin_path = tmp / "SNIPER-HTTP-ID-INDEX.json"
        pin_path.write_text("{}")

        with pytest.raises(ValueError, match="root mutlak olmalı"):
            verify_http_catalog(
                root=root,
                pin_path=pin_path,
                expected_pin_sha256="0000000000000000000000000000000000000000000000000000000000000000",
                expected_count=2,
                mapping_sha256="0000000000000000000000000000000000000000000000000000000000000000",
            )


def test_pin_symlink_fails():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root = tmp / "catalog"
        root.mkdir()
        pin_path = tmp / "pin.json"
        pin_path.write_text("{}")
        link_pin = tmp / "link.json"
        link_pin.symlink_to(pin_path)

        with pytest.raises(ValueError, match="pin_path sembolik bağ olmamalı"):
            verify_http_catalog(
                root=root,
                pin_path=link_pin,
                expected_pin_sha256="0000000000000000000000000000000000000000000000000000000000000000",
                expected_count=2,
                mapping_sha256="0000000000000000000000000000000000000000000000000000000000000000",
            )
