from __future__ import annotations

import hashlib
import json
from pathlib import Path

import iac_tf_project


def _tree_sha(files: dict[str, str], prefix: str) -> str:
    rows = [
        [path[len(prefix) + 1 :], hashlib.sha256(text.encode()).hexdigest()]
        for path, text in sorted(files.items())
        if path.startswith(prefix + "/")
    ]
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def _files() -> dict[str, str]:
    return {
        "main.tf": (
            'module "db" {\n'
            '  source = "git::https://modules.example/db.git"\n'
            '  version = "1.2.3"\n'
            '  publicly_accessible = true\n'
            '}\n'
        ),
        ".sniper/terraform-modules/db/variables.tf": (
            'variable "publicly_accessible" { default = false }\n'
        ),
        ".sniper/terraform-modules/db/main.tf": (
            'resource "aws_db_instance" "this" {\n'
            '  storage_encrypted = true\n'
            '  publicly_accessible = var.publicly_accessible\n'
            '}\n'
        ),
    }


def test_exact_pinned_offline_mirror_is_analyzed_as_remote_module() -> None:
    files = _files()
    prefix = ".sniper/terraform-modules/db"
    manifest = {
        "format": "sniper-terraform-module-mirror/1",
        "modules": [{
            "source": "git::https://modules.example/db.git",
            "version": "1.2.3",
            "path": prefix,
            "tree_sha256": _tree_sha(files, prefix),
        }],
    }

    result = iac_tf_project.analyze_files(files, mirror_manifest=manifest)

    findings = result[prefix + "/main.tf"].findings
    assert result.analysis_complete is True
    assert [(item["id"], item["line"]) for item in findings] == [("SNP-IAC-TF-005", 3)]
    assert findings[0]["resource"] == "module.db.aws_db_instance.this"
    assert "main.tf:1" in findings[0]["evidence"]


def test_tampered_or_unpinned_remote_module_fails_closed() -> None:
    files = _files()
    prefix = ".sniper/terraform-modules/db"
    bad_manifest = {
        "format": "sniper-terraform-module-mirror/1",
        "modules": [{
            "source": "git::https://modules.example/db.git",
            "version": "1.2.3",
            "path": prefix,
            "tree_sha256": "f" * 64,
        }],
    }

    tampered = iac_tf_project.analyze_files(files, mirror_manifest=bad_manifest)
    unpinned = iac_tf_project.analyze_files(files, mirror_manifest=None)

    assert tampered.analysis_complete is False
    assert "remote-module-mirror-digest" in tampered.limitations
    assert unpinned.analysis_complete is False
    assert "remote-module-unverified" in unpinned.limitations
    assert not tampered[prefix + "/main.tf"].findings
    assert not unpinned[prefix + "/main.tf"].findings


def test_mirror_path_traversal_and_floating_version_are_not_trusted() -> None:
    files = _files()
    manifest = {
        "format": "sniper-terraform-module-mirror/1",
        "modules": [{
            "source": "git::https://modules.example/db.git",
            "version": ">= 1.0",
            "path": "../outside",
            "tree_sha256": "a" * 64,
        }],
    }

    result = iac_tf_project.analyze_files(files, mirror_manifest=manifest)

    assert result.analysis_complete is False
    assert "remote-module-mirror-invalid" in result.limitations


def test_scan_tree_reads_only_the_pinned_in_repository_manifest(tmp_path: Path) -> None:
    files = _files()
    for relative, text in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    prefix = ".sniper/terraform-modules/db"
    manifest = {
        "format": "sniper-terraform-module-mirror/1",
        "modules": [{
            "source": "git::https://modules.example/db.git",
            "version": "1.2.3",
            "path": prefix,
            "tree_sha256": _tree_sha(files, prefix),
        }],
    }
    manifest_path = tmp_path / iac_tf_project.MIRROR_MANIFEST_PATH
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = iac_tf_project.scan_tree(tmp_path, set())

    assert result.analysis_complete is True
    assert result[prefix + "/main.tf"].findings[0]["resource"] == "module.db.aws_db_instance.this"
