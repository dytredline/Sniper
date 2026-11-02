from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

import container_scan
import osv_db_refresh


def _rpm_header() -> bytes:
    tags = (
        (1000, 6, "openssl-libs"),
        (1001, 6, "3.0.7"),
        (1002, 6, "24.el9"),
        (1003, 4, 1),
        (1022, 6, "aarch64"),
        (1044, 6, "openssl-3.0.7-24.el9.src.rpm"),
    )
    index = bytearray()
    data = bytearray()
    for tag, kind, value in tags:
        if kind == 6:
            offset = len(data)
            data.extend(value.encode("utf-8") + b"\0")
        else:
            while len(data) % 4:
                data.append(0)
            offset = len(data)
            data.extend(struct.pack(">I", value))
        index.extend(struct.pack(">IIII", tag, kind, offset, 1))
    return struct.pack(">II", len(tags), len(data)) + bytes(index) + bytes(data)


def _real_berkeley_database(tmp_path: Path) -> Path:
    perl = shutil.which("perl")
    if not perl:
        pytest.skip("system Perl is unavailable")
    probe = subprocess.run(
        [perl, "-MDB_File", "-e", "print qq($DB_File::db_ver\\n)"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if probe.returncode != 0 or not probe.stdout.startswith("5."):
        pytest.skip("Perl DB_File backed by Berkeley DB 5.x is unavailable")
    value = tmp_path / "header.bin"
    value.write_bytes(_rpm_header())
    database = tmp_path / "Packages"
    writer = r'''
use strict;
use warnings;
my ($database, $value_file) = @ARGV;
open my $value_fh, '<:raw', $value_file or die "value_open";
local $/;
my $value = <$value_fh>;
close $value_fh;
tie my %packages, 'DB_File', $database, O_CREAT|O_RDWR, 0600, $DB_HASH or die "db_open";
$packages{pack('L', 1)} = $value;
untie %packages;
'''
    subprocess.run(
        [perl, "-MDB_File", "-MFcntl=O_CREAT,O_RDWR", "-e", writer, str(database), str(value)],
        capture_output=True,
        timeout=10,
        check=True,
    )
    assert database.stat().st_size >= 4096
    assert container_scan.detect_legacy_rpmdb(database.read_bytes(), "var/lib/rpm/Packages") == "berkeleydb"
    return database


def _empty_osv_root(tmp_path: Path) -> Path:
    ecosystem = "Red Hat Enterprise Linux:9"
    root = tmp_path / "osv"
    slug = osv_db_refresh._slug(ecosystem)
    archive = root / "generations" / slug / "g1" / "db-cache" / "osv-scalibr" / ecosystem / "all.zip"
    archive.parent.mkdir(parents=True)
    import zipfile

    with zipfile.ZipFile(archive, "w"):
        pass
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    osv_db_refresh.manifest_path(root, ecosystem).write_text(
        json.dumps({
            "ecosystem": ecosystem,
            "scanner_cache_path": str(archive),
            "sha256": digest,
            "generation": "g1",
            "retrieved_utc": "2026-10-31T00:00:00+00:00",
        }),
        encoding="utf-8",
    )
    return root


def test_real_berkeley_runtime_extracts_rpm_header(tmp_path: Path) -> None:
    database = _real_berkeley_database(tmp_path)

    packages = container_scan.parse_rpm_berkeley(database.read_bytes(), "var/lib/rpm/Packages")

    assert packages == [{
        "type": "rpm",
        "name": "openssl-libs",
        "version": "1:3.0.7-24.el9",
        "source": "openssl",
        "source_version": "1:3.0.7-24.el9",
        "arch": "aarch64",
        "db": "var/lib/rpm/Packages",
        "line": 1,
    }]


def test_real_berkeley_runtime_is_used_by_rootfs_inventory(tmp_path: Path) -> None:
    database = _real_berkeley_database(tmp_path)
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc/os-release").write_text(
        'ID="rhel"\nVERSION_ID="9.4"\n', encoding="utf-8"
    )
    target = rootfs / "var/lib/rpm/Packages"
    target.parent.mkdir(parents=True)
    target.write_bytes(database.read_bytes())
    osv = _empty_osv_root(tmp_path)

    result = container_scan.scan_image(str(rootfs), osv_root=osv, allowed_roots=(tmp_path,))

    package_check = next(item for item in result["checks"] if item["id"] == "os_packages")
    assert package_check["status"] == "pass"
    assert result["container"]["package_inventory"] == {
        "status": "available",
        "package_type": "rpm",
        "covered_files": ["var/lib/rpm/Packages"],
        "unsupported_files": [],
        "reason": None,
    }
    assert result["components"][0]["name"] == "openssl-libs"


def test_corrupt_berkeley_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(container_scan.ContainerScanError, match="BerkeleyDB"):
        container_scan.parse_rpm_berkeley(b"not-a-database", "var/lib/rpm/Packages")
