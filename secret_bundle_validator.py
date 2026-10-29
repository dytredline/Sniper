from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath

MANIFEST_FORMAT = "secret-scan-bundle-manifest-v1"
MANIFEST_SCOPE = "explicit_in_memory_bundle_only"
MIN_BUNDLE_FILES = 1
MAX_BUNDLE_FILES = 16
MAX_FILE_UTF8_BYTES = 65_536
MAX_TOTAL_UTF8_BYTES = 262_144
MAX_RELATIVE_PATH_LENGTH = 255

FORBIDDEN_DIR_SEGMENTS = frozenset({".git", ".hg", ".svn"})
FORBIDDEN_BASENAMES = frozenset({
    ".gitleaks.toml",
    "gitleaks.toml",
    ".gitleaksignore",
    ".trufflehogignore",
    ".trufflehog.yaml",
    ".trufflehog.yml",
    ".semgrepignore",
    ".sniperignore",
})


def _validate_relative_path(raw_path: object) -> str:
    if not isinstance(raw_path, str):
        raise ValueError("relative_path bir metin olmalı.")
    if not raw_path or raw_path.strip() != raw_path:
        raise ValueError("relative_path boş olmayan, başında/sonunda boşluk olmayan bir metin olmalı.")
    if len(raw_path) > MAX_RELATIVE_PATH_LENGTH:
        raise ValueError("relative_path en fazla 255 karakter olabilir.")
    if "\x00" in raw_path or any(ord(ch) < 32 for ch in raw_path):
        raise ValueError("relative_path NUL baytı veya denetim karakteri içermemeli.")
    if "\\" in raw_path:
        raise ValueError("relative_path ters eğik çizgi içermemeli.")
    if (
        raw_path.startswith("/")
        or raw_path.startswith("~")
        or (len(raw_path) >= 2 and raw_path[1] == ":")
        or PurePosixPath(raw_path).is_absolute()
    ):
        raise ValueError("Mutlak veya ev dizinine göreli dosya sistemi yollarına izin verilmiyor.")
    if raw_path.endswith("/") or "//" in raw_path:
        raise ValueError("relative_path normalleştirilmiş göreli bir dosya yolu olmalı.")

    segments = raw_path.split("/")
    for segment in segments:
        if not segment or segment in (".", ".."):
            raise ValueError("Üst dizin veya nokta yol aşımı bölümlerine izin verilmiyor.")
        if segment.casefold() in FORBIDDEN_DIR_SEGMENTS:
            raise ValueError("Gizli .git dizini yollarına ve kancalara izin verilmiyor.")

    if segments[-1].casefold() in FORBIDDEN_BASENAMES:
        raise ValueError("Pakette tarayıcı yapılandırmasını geçersiz kılan dosyalara izin verilmiyor.")

    return raw_path


def validate_bounded_secret_scan_bundle(files: object) -> dict[str, object]:
    """Validate an explicit in-memory multi-file bundle for bounded secret scanning.

    Enforces strict local scope boundaries: no arbitrary host paths, no parent traversal,
    no .git hooks/configs, bounded file count (1..16), bounded per-file UTF-8 size (<= 64 KiB),
    and bounded total UTF-8 size (<= 256 KiB).
    """
    if not isinstance(files, list):
        raise ValueError("files dosya girdisi nesnelerinden oluşan bir liste olmalı.")
    if len(files) < MIN_BUNDLE_FILES:
        raise ValueError("files paketi en az 1 dosya içermeli.")
    if len(files) > MAX_BUNDLE_FILES:
        raise ValueError(f"files paketi azami {MAX_BUNDLE_FILES} dosya sınırını aşıyor.")

    seen_paths: set[str] = set()
    manifest_files: list[dict[str, object]] = []
    total_bytes = 0

    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("Her dosya girdisi bir sözlük olmalı.")
        if set(entry.keys()) != {"relative_path", "content"}:
            raise ValueError("Her dosya girdisi tam olarak 'relative_path' ve 'content' içermeli.")

        rel_path = _validate_relative_path(entry.get("relative_path"))
        if rel_path in seen_paths:
            raise ValueError("Yinelenen relative_path girdilerine izin verilmiyor.")
        seen_paths.add(rel_path)

        content = entry.get("content")
        if not isinstance(content, str):
            raise ValueError("Dosya içeriği bir metin olmalı.")
        if "\x00" in content:
            raise ValueError("Dosya içeriği NUL baytı içermemeli.")

        try:
            content_bytes = content.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("Dosya içeriği geçerli UTF-8 olmalı.") from exc

        size_bytes = len(content_bytes)
        if size_bytes > MAX_FILE_UTF8_BYTES:
            raise ValueError(f"Dosya azami {MAX_FILE_UTF8_BYTES} UTF-8 bayt boyutunu aşıyor.")

        total_bytes += size_bytes
        if total_bytes > MAX_TOTAL_UTF8_BYTES:
            raise ValueError(
                f"Paket toplam boyutu azami {MAX_TOTAL_UTF8_BYTES} UTF-8 baytı aşıyor."
            )

        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        manifest_files.append(
            {
                "relative_path": rel_path,
                "size_bytes": size_bytes,
                "sha256": file_sha256,
            }
        )

    canonical_payload = {
        "format": MANIFEST_FORMAT,
        "scope": MANIFEST_SCOPE,
        "file_count": len(manifest_files),
        "total_bytes": total_bytes,
        "files": sorted(manifest_files, key=lambda item: str(item["relative_path"])),
    }
    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    bundle_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    return {
        "format": MANIFEST_FORMAT,
        "scope": MANIFEST_SCOPE,
        "file_count": len(manifest_files),
        "total_bytes": total_bytes,
        "files": manifest_files,
        "bundle_sha256": bundle_sha256,
    }
