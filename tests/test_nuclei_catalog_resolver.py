import hashlib
import json
import os
import pathlib
from typing import List, Tuple

import pytest

from nuclei_catalog_resolver import resolve_http_template_paths


def _make_test_catalog(tmp_path: pathlib.Path, real_file_id: str, real_file_content: bytes) -> Tuple[str, pathlib.Path]:
    # Build index with exactly 11655 rows
    count = 11655
    # One real row
    real_rel_path = f"http/a/b/{real_file_id}.yaml"
    real_sha = hashlib.sha256(real_file_content).hexdigest()
    # Remaining dummy rows referencing nonexistent files
    rows: List[List[str]] = []
    rows.append([real_file_id, real_rel_path, real_sha])
    
    for i in range(1, count):
        row_id = f"template_{i:05d}"
        row_rel = f"http/c/d/{row_id}.yaml"
        row_sha = "a" * 64  # dummy SHA
        rows.append([row_id, row_rel, row_sha])
    
    # Build index
    index_data = {
        "version": "v10.5.0",
        "count": count,
        "sha256": "b" * 64,
        "ids_paths_hashes": rows
    }
    index_bytes = json.dumps(index_data, separators=(",", ":")).encode("utf-8")
    index_sha = hashlib.sha256(index_bytes).hexdigest()
    
    # Write index
    index_path = tmp_path / "SNIPER-HTTP-ID-INDEX.json"
    index_path.write_bytes(index_bytes)
    
    # Create real file
    real_full_path = tmp_path / real_rel_path
    real_full_path.parent.mkdir(parents=True, exist_ok=True)
    real_full_path.write_bytes(real_file_content)
    
    return index_sha, tmp_path


def test_resolve_http_template_paths_real_file(tmp_path: pathlib.Path) -> None:
    # Setup catalog
    real_content = b"# real template\n"
    index_sha, catalog_root = _make_test_catalog(tmp_path, "real_template", real_content)
    
    # Resolve
    results = resolve_http_template_paths(catalog_root, ["real_template"], index_sha)
    expected_path = catalog_root / "http/a/b/real_template.yaml"
    assert results["real_template"] == expected_path


def test_resolve_http_template_paths_accepts_pinned_yml_file(tmp_path: pathlib.Path) -> None:
    relative = "http/a/b/alternate.yml"
    content = b"id: alternate\n"
    digest = hashlib.sha256(content).hexdigest()
    index_data = {
        "version": "v10.5.0", "count": 1, "sha256": "b" * 64,
        "ids_paths_hashes": [["alternate", relative, digest]],
    }
    index_bytes = json.dumps(index_data, separators=(",", ":")).encode("utf-8")
    (tmp_path / "SNIPER-HTTP-ID-INDEX.json").write_bytes(index_bytes)
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(content)

    result = resolve_http_template_paths(
        tmp_path, ["alternate"], hashlib.sha256(index_bytes).hexdigest())
    assert result["alternate"] == target


def test_resolve_http_template_paths_wrong_index_pin(tmp_path: pathlib.Path) -> None:
    real_content = b"# real\n"
    index_sha, catalog_root = _make_test_catalog(tmp_path, "real_template", real_content)
    
    # Wrong index SHA
    with pytest.raises(ValueError, match="Dizin SHA256 değeri uyuşmuyor"):
        resolve_http_template_paths(catalog_root, ["real_template"], "x" * 64)


def test_resolve_http_template_paths_altered_content(tmp_path: pathlib.Path) -> None:
    real_content = b"# real\n"
    index_sha, catalog_root = _make_test_catalog(tmp_path, "real_template", real_content)
    
    # Alter file after index creation
    altered_path = catalog_root / "http/a/b/real_template.yaml"
    altered_path.write_bytes(b"# altered\n")
    
    with pytest.raises(ValueError, match="SHA256 uyuşmuyor"):
        resolve_http_template_paths(catalog_root, ["real_template"], index_sha)
