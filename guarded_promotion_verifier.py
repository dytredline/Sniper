from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path

RECEIPT_FORMAT = "guarded-promotion-verification-v1"
MIN_BACKUP_ARCHIVE_BYTES = 1024
EXCLUDED_DIR_NAMES = frozenset({"data", "__pycache__", ".pytest_cache"})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _coerce_path(value: Path | str, label: str) -> Path:
    if isinstance(value, Path):
        return value
    if isinstance(value, str) and value.strip():
        return Path(value)
    raise ValueError(f"{label} boş olmayan bir Path veya metin olmalı.")


def _sha256_regular_file(path: Path, label: str) -> tuple[str, int]:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} eksik veya okunamıyor.") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{label} sembolik bağ olmamalı.")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{label} normal bir dosya olmalı.")

    digest = hashlib.sha256()
    total_bytes = 0
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
                total_bytes += len(chunk)
    except OSError as exc:
        raise ValueError(f"{label} okunamadı.") from exc

    return digest.hexdigest(), total_bytes


def _collect_tree_manifest(root: Path, label: str) -> dict[str, str]:
    try:
        st = os.lstat(root)
    except OSError as exc:
        raise ValueError(f"{label} yok.") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{label} sembolik bağ olmamalı.")
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{label} bir dizin olmalı.")

    manifest: dict[str, str] = {}

    def _walk(current: Path) -> None:
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError as exc:
            raise ValueError(f"{label} içindeki dizin taranamadı.") from exc

        for entry in entries:
            if entry.name in EXCLUDED_DIR_NAMES:
                continue
            entry_path = Path(entry.path)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ValueError(f"{label} içindeki girdinin bilgisi alınamadı.") from exc

            if stat.S_ISLNK(entry_stat.st_mode):
                raise ValueError(f"{label} içinde sembolik bağ girdisine izin verilmiyor: {entry.name}")
            if stat.S_ISDIR(entry_stat.st_mode):
                _walk(entry_path)
            elif stat.S_ISREG(entry_stat.st_mode):
                rel_posix = entry_path.relative_to(root).as_posix()
                file_sha256, _ = _sha256_regular_file(entry_path, f"{label}:{rel_posix}")
                manifest[rel_posix] = file_sha256
            else:
                raise ValueError(f"{label} içinde desteklenmeyen, normal olmayan dosya girdisi: {entry.name}")

    _walk(root)
    return manifest


def _verify_sqlite_readonly_integrity(db_path: Path) -> str:
    resolved_uri = f"{db_path.resolve().as_uri()}?mode=ro"
    try:
        conn = sqlite3.connect(resolved_uri, uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise ValueError("SQLite veritabanı salt okunur kipte açılamıyor.") from exc

    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA query_only = ON;")
        cursor.execute("PRAGMA integrity_check;")
        rows = cursor.fetchall()
    except sqlite3.Error as exc:
        raise ValueError("SQLite PRAGMA integrity_check başarısız oldu.") from exc
    finally:
        conn.close()

    if len(rows) != 1 or len(rows[0]) != 1 or not isinstance(rows[0][0], str):
        raise ValueError("SQLite integrity_check beklenmeyen biçimde sonuç döndürdü.")
    status = rows[0][0].strip().lower()
    if status != "ok":
        raise ValueError(f"SQLite integrity_check geçmedi: {status}")
    return "ok"


def verify_guarded_promotion_state(
    *,
    candidate_dir: Path | str,
    installed_dir: Path | str,
    backup_archive: Path | str,
    sqlite_db_path: Path | str,
    pre_db_sha256: str,
) -> dict[str, object]:
    """Verify read-only guarded promotion invariants, backup archive, and SQLite DB parity."""
    if not isinstance(pre_db_sha256, str):
        raise ValueError("pre_db_sha256 64 karakterlik onaltılık bir metin olmalı.")
    normalized_pre_sha = pre_db_sha256.strip().lower()
    if not SHA256_RE.fullmatch(normalized_pre_sha):
        raise ValueError("pre_db_sha256 geçerli, 64 karakterlik küçük harfli onaltılık bir SHA-256 özeti olmalı.")

    cand_path = _coerce_path(candidate_dir, "candidate_dir")
    inst_path = _coerce_path(installed_dir, "installed_dir")
    backup_path = _coerce_path(backup_archive, "backup_archive")
    db_path = _coerce_path(sqlite_db_path, "sqlite_db_path")

    if not backup_path.name.endswith(".tar.gz"):
        raise ValueError("backup_archive bir .tar.gz dosyası olmalı.")
    backup_sha256, backup_size = _sha256_regular_file(backup_path, "backup_archive")
    if backup_size <= MIN_BACKUP_ARCHIVE_BYTES:
        raise ValueError(
            f"backup_archive {MIN_BACKUP_ARCHIVE_BYTES} bayttan büyük olmalı."
        )

    db_sha_before, db_size = _sha256_regular_file(db_path, "sqlite_db_path")
    if db_size <= 0:
        raise ValueError("sqlite_db_path boş olmamalı.")
    if db_sha_before != normalized_pre_sha:
        raise ValueError("sqlite_db_path SHA-256 değeri pre_db_sha256 ile eşleşmiyor.")

    integrity_status = _verify_sqlite_readonly_integrity(db_path)

    db_sha_after, _ = _sha256_regular_file(db_path, "sqlite_db_path")
    if db_sha_after != normalized_pre_sha:
        raise ValueError("sqlite_db_path salt okunur bütünlük denetimi sırasında değişti.")

    candidate_manifest = _collect_tree_manifest(cand_path, "candidate_dir")
    installed_manifest = _collect_tree_manifest(inst_path, "installed_dir")

    if not candidate_manifest:
        raise ValueError("candidate_dir doğrulanabilir normal dosya içermiyor.")
    if set(candidate_manifest.keys()) != set(installed_manifest.keys()):
        raise ValueError("candidate_dir ve installed_dir dosya kümeleri farklı.")

    for rel_path, cand_digest in candidate_manifest.items():
        if installed_manifest.get(rel_path) != cand_digest:
            raise ValueError(f"Kurulu dosya içeriği adaydan farklı: {rel_path}")

    manifest_entries = [
        {"path": rel_path, "sha256": digest}
        for rel_path, digest in sorted(candidate_manifest.items())
    ]
    manifest_sha256 = hashlib.sha256(
        json.dumps(manifest_entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    receipt_payload: dict[str, object] = {
        "format": RECEIPT_FORMAT,
        "backup_archive_sha256": backup_sha256,
        "backup_archive_size_bytes": backup_size,
        "sqlite_db_sha256": db_sha_after,
        "sqlite_integrity_check": integrity_status,
        "true_live_db_write": False,
        "candidate_installed_match": True,
        "verified_file_count": len(candidate_manifest),
        "manifest_sha256": manifest_sha256,
    }
    receipt_sha256 = hashlib.sha256(
        json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return {
        **receipt_payload,
        "receipt_sha256": receipt_sha256,
    }
