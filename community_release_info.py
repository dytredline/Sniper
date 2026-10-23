"""Community source-distribution version and database-backup helpers.

This module intentionally contains no commercial packaging, installer,
licensing, customer binding, or native-binary delivery behavior.  It is the
small compatibility surface used by the Community web runtime after the
public-source assembler removes the private delivery implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any

from engine_identity import engine_fingerprint


FORMAT = "sniper-community-version/1"
BACKUP_META = "backup.json"


class CommunityReleaseError(RuntimeError):
    """A Community backup/version operation could not be completed safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = Path(path).lstat()
    except OSError as exc:
        raise CommunityReleaseError(f"{label} is not readable") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise CommunityReleaseError(f"{label} must be a regular file")
    return info


def backup_database(source: Path, target: Path) -> dict[str, Any]:
    """Create a consistent SQLite backup and verify it before returning."""
    source, target = Path(source), Path(target)
    _regular_file(source, "source database")
    if target.exists() or target.is_symlink():
        raise CommunityReleaseError("backup destination already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    result = ""
    try:
        source_connection = sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True)
        try:
            destination_connection = sqlite3.connect(target)
            try:
                source_connection.backup(destination_connection)
                result = str(destination_connection.execute("PRAGMA integrity_check").fetchone()[0])
            finally:
                destination_connection.close()
        finally:
            source_connection.close()
        os.chmod(target, 0o600)
        if result != "ok":
            raise CommunityReleaseError("backup database failed its integrity check")
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return {"path": str(target), "sha256": sha256_file(target), "integrity": result}


def restore_database(backup: Path, live: Path) -> None:
    """Restore a previously verified SQLite backup through SQLite's backup API."""
    backup, live = Path(backup), Path(live)
    _regular_file(backup, "backup database")
    source_connection = sqlite3.connect(f"file:{backup.resolve()}?mode=ro", uri=True)
    try:
        destination_connection = sqlite3.connect(live)
        try:
            source_connection.backup(destination_connection)
            result = str(destination_connection.execute("PRAGMA integrity_check").fetchone()[0])
        finally:
            destination_connection.close()
    finally:
        source_connection.close()
    if result != "ok":
        raise CommunityReleaseError("restored database failed its integrity check")


def list_backups(backup_dir: Path) -> list[dict[str, Any]]:
    """List bounded, metadata-backed legacy backup directories without following links."""
    backup_dir = Path(backup_dir)
    try:
        root_info = backup_dir.lstat()
    except OSError:
        return []
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        return []

    output: list[dict[str, Any]] = []
    try:
        children = sorted(backup_dir.iterdir(), reverse=True)
    except OSError:
        return []
    for child in children[:200]:
        try:
            child_info = child.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(child_info.st_mode) or stat.S_ISLNK(child_info.st_mode):
            continue
        metadata = read_json(child / BACKUP_META, None)
        if not isinstance(metadata, dict):
            continue
        total = 0
        try:
            for item in child.iterdir():
                info = item.lstat()
                if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    total += info.st_size
        except OSError:
            continue
        output.append({
            "id": child.name,
            "created_at": metadata.get("created_at"),
            "version": metadata.get("version"),
            "reason": metadata.get("reason"),
            "has_db": bool(metadata.get("db")),
            "bytes": total,
        })
    return output


def _product_version(app_root: Path) -> str | None:
    path = Path(app_root) / "version.py"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    return match.group(1) if match else None


def system_version_payload(
    app_root: Path,
    data_dir: Path,
    backup_dir: Path | None = None,
    *,
    running_release: Any = None,
) -> dict[str, Any]:
    """Return read-only Community source/version state for the local UI.

    ``running_release`` is accepted only to preserve the web caller signature
    during source assembly.  Community distributions do not consume installed
    commercial package records.
    """
    del data_dir, running_release
    app_root = Path(app_root)
    backups = Path(backup_dir) if backup_dir is not None else app_root.parent / "backups"
    return {
        "format": FORMAT,
        "product_version": _product_version(app_root),
        "distribution": "community-source",
        "release": None,
        "packaged": False,
        "restart_pending": False,
        "installed_version": None,
        "engine_id": engine_fingerprint(app_root),
        "installed_at": None,
        "last_update": None,
        "history": [],
        "backups": list_backups(backups)[:20],
        "maintenance_note": "Replace the Community source tree only after reviewing a new archive and its SHA-256 manifest.",
        "ui_updates": False,
    }
