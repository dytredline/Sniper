#!/usr/bin/env python3
"""Build a deterministic, read-only Nuclei v10.5.0 HTTP catalog from its official tag archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Any


VERSION = "v10.5.0"
ARCHIVE_SHA256 = "80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41"
EXPECTED_TEMPLATE_COUNT = 11_655
ARCHIVE_PREFIX = "nuclei-templates-10.5.0"
MAPPING_PATH = "http/technologies/wappalyzer-mapping.yml"
PIN_NAME = "SNIPER-HTTP-CATALOG-PIN-v2.json"
INDEX_NAME = "SNIPER-HTTP-ID-INDEX.json"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TEMPLATE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_ARCHIVE_BYTES = 100_000_000
_MAX_MEMBERS = 25_000
_MAX_FILE_BYTES = 12_000_000
_MAX_TOTAL_BYTES = 1_000_000_000


class CatalogInstallError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size < 1
                or info.st_size > _MAX_ARCHIVE_BYTES):
            raise OSError("unsafe archive")
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise CatalogInstallError("Nuclei catalog archive is unavailable") from exc


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _rows_sha(rows: list[list[str]]) -> str:
    raw = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _template_id(raw: bytes, relative: str) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CatalogInstallError(f"Template is not UTF-8: {relative}") from exc
    for line in text.splitlines():
        if not line.startswith("id:"):
            continue
        value = line[3:].strip()
        if " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if _TEMPLATE_ID.fullmatch(value):
            return value
        break
    raise CatalogInstallError(f"Invalid or missing template ID: {relative}")


def _member_relative(member: tarfile.TarInfo) -> str | None:
    path = PurePosixPath(member.name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CatalogInstallError("Archive contains an unsafe path")
    if not path.parts or path.parts[0] != ARCHIVE_PREFIX:
        raise CatalogInstallError("Archive root does not match Nuclei v10.5.0")
    inner = PurePosixPath(*path.parts[1:])
    if not inner.parts or inner.parts[0] != "http":
        return None
    if inner.suffix.lower() not in {".yaml", ".yml"}:
        return None
    return inner.as_posix()


def install_catalog(
    archive: Path,
    destination: Path,
    *,
    expected_archive_sha256: str = ARCHIVE_SHA256,
    expected_template_count: int = EXPECTED_TEMPLATE_COUNT,
) -> dict[str, object]:
    archive = Path(archive)
    destination = Path(destination)
    if not _HEX64.fullmatch(expected_archive_sha256):
        raise CatalogInstallError("Invalid expected archive SHA-256")
    if type(expected_template_count) is not int or not 1 <= expected_template_count <= 20_000:
        raise CatalogInstallError("Invalid expected template count")
    if destination.exists() or destination.is_symlink():
        raise CatalogInstallError("Catalog destination already exists")
    parent = destination.parent
    try:
        if (not destination.is_absolute() or parent.is_symlink()
                or parent.resolve(strict=True) != parent or not parent.is_dir()):
            raise OSError("unsafe destination")
    except OSError as exc:
        raise CatalogInstallError("Catalog destination parent is unsafe") from exc
    actual_archive_sha = _sha256(archive)
    if actual_archive_sha != expected_archive_sha256:
        raise CatalogInstallError("Nuclei catalog archive SHA-256 mismatch")

    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=parent))
    rows: list[list[str]] = []
    id_rows: list[list[str]] = []
    seen_paths: set[str] = set()
    seen_ids: set[str] = set()
    mapping_sha = ""
    total = 0
    try:
        try:
            with tarfile.open(archive, mode="r:gz") as bundle:
                members = bundle.getmembers()
                if len(members) > _MAX_MEMBERS:
                    raise CatalogInstallError("Nuclei catalog archive has too many members")
                for member in members:
                    relative = _member_relative(member)
                    if relative is None:
                        continue
                    if not member.isreg():
                        raise CatalogInstallError("HTTP catalog member must be a regular file")
                    if relative in seen_paths or not 1 <= member.size <= _MAX_FILE_BYTES:
                        raise CatalogInstallError("HTTP catalog member is duplicate or oversized")
                    seen_paths.add(relative)
                    total += member.size
                    if total > _MAX_TOTAL_BYTES:
                        raise CatalogInstallError("HTTP catalog exceeds its extraction budget")
                    source = bundle.extractfile(member)
                    if source is None:
                        raise CatalogInstallError("HTTP catalog member cannot be read")
                    with source:
                        raw = source.read(_MAX_FILE_BYTES + 1)
                    if len(raw) != member.size:
                        raise CatalogInstallError("HTTP catalog member was only partially read")
                    target = staging.joinpath(*PurePosixPath(relative).parts)
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    descriptor = os.open(
                        target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(raw)
                    digest = hashlib.sha256(raw).hexdigest()
                    if relative == MAPPING_PATH:
                        mapping_sha = digest
                        continue
                    template_id = _template_id(raw, relative)
                    if template_id in seen_ids:
                        raise CatalogInstallError(f"Duplicate template ID: {template_id}")
                    seen_ids.add(template_id)
                    rows.append([relative, digest])
                    id_rows.append([template_id, relative, digest])
        except (OSError, tarfile.TarError) as exc:
            raise CatalogInstallError("Nuclei catalog archive cannot be processed") from exc

        if not mapping_sha:
            raise CatalogInstallError("Pinned Wappalyzer mapping is absent")
        if len(rows) != expected_template_count:
            raise CatalogInstallError(
                f"Nuclei template count mismatch: expected {expected_template_count}, got {len(rows)}")
        rows.sort(key=lambda item: item[0])
        id_rows.sort(key=lambda item: item[0])
        pin_doc = {
            "version": VERSION, "count": len(rows), "paths_and_hashes": rows,
            "scope": "http", "sha256": _rows_sha(rows),
        }
        index_doc = {
            "version": VERSION, "count": len(id_rows), "ids_paths_hashes": id_rows,
            "sha256": _rows_sha(id_rows),
        }
        pin_bytes = _canonical_json(pin_doc)
        index_bytes = _canonical_json(index_doc)
        (staging / PIN_NAME).write_bytes(pin_bytes)
        (staging / INDEX_NAME).write_bytes(index_bytes)
        for path in sorted(staging.rglob("*"), reverse=True):
            os.chmod(path, 0o555 if path.is_dir() else 0o444)
        os.chmod(staging, 0o555)
        os.replace(staging, destination)
        return {
            "format": "sniper-nuclei-http-catalog-install-v1",
            "version": VERSION,
            "template_count": len(rows),
            "archive_sha256": actual_archive_sha,
            "pin_sha256": hashlib.sha256(pin_bytes).hexdigest(),
            "index_sha256": hashlib.sha256(index_bytes).hexdigest(),
            "mapping_sha256": mapping_sha,
        }
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = install_catalog(args.archive, args.destination)
    except CatalogInstallError as exc:
        print(f"nuclei catalog install: FAIL ({exc})", file=os.sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
